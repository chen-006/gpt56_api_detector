from __future__ import annotations

import json
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

from gpt56_request_metadata import (
    MetadataOptions,
    build_request_metadata,
    estimate_usage,
    extract_request_id,
    extract_usage,
    format_attempt_logs,
    lookup_client_egress_ip,
)
from gpt56_juice_probe import run_juice_request
from gpt56_reasoning_probe import ProbeError, ResponsesClient
from gpt56_report_html import render_report_html


class _Headers(dict):
    def items(self):
        return super().items()


class _Response:
    status = 200

    def __init__(self, body: bytes, headers: dict[str, str] | None = None):
        self._body = body
        self.headers = _Headers(headers or {})

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, *_args):
        return self._body


class RequestMetadataTests(unittest.TestCase):
    def test_request_id_header_and_usage_are_normalized(self):
        request_id, source = extract_request_id({"X-Request-ID": "srv-123"})
        self.assertEqual((request_id, source), ("srv-123", "x-request-id"))
        usage = extract_usage({"usage": {"input_tokens": 8, "output_tokens": 3, "total_tokens": 11}})
        self.assertEqual(usage["total_tokens"], 11)
        self.assertEqual(usage["source"], "provider_usage")

    def test_sensitive_ip_fields_are_absent_by_default(self):
        metadata = build_request_metadata(
            options=MetadataOptions(),
            correlation_id="local-1",
            url="https://example.test/v1/responses",
            payload={"input": [{"role": "user", "content": "hello"}]},
            response={"usage": {"total_tokens": 2}},
            response_headers={"x-request-id": "srv-1"},
            status=200,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            elapsed_ms=4,
            response_size_bytes=20,
        )
        self.assertNotIn("server_ips", metadata)
        self.assertNotIn("client_egress_ip", metadata)
        self.assertEqual(metadata["server_request_id"], "srv-1")

    def test_estimate_is_explicitly_labeled(self):
        estimate = estimate_usage(
            {"input": [{"role": "user", "content": "abcdefgh"}]},
            {"output_text": "ijkl"},
        )
        self.assertEqual(estimate["source"], "estimated")
        self.assertIn("Approximate", estimate["warning"])
        self.assertEqual(estimate["total_tokens"], 3)

    @patch("gpt56_request_metadata.urllib.request.urlopen")
    def test_client_egress_lookup_accepts_json_ip(self, urlopen):
        urlopen.return_value = _Response(json.dumps({"ip": "203.0.113.7"}).encode())
        self.assertEqual(lookup_client_egress_ip("https://ip.test", timeout=1), "203.0.113.7")
        urlopen.assert_called_once()

    @patch("gpt56_reasoning_probe.urllib.request.urlopen")
    def test_responses_client_records_metadata_and_sends_correlation_header(self, urlopen):
        body = json.dumps(
            {
                "id": "resp-42",
                "output_text": "READY",
                "usage": {"input_tokens": 4, "output_tokens": 1, "total_tokens": 5},
            }
        ).encode()
        urlopen.return_value = _Response(body, {"X-Request-ID": "server-42"})
        client = ResponsesClient("https://api.test/v1", "secret", 3)
        response, metadata = client.post({"model": "gpt-5.6-sol", "input": [{"content": "hi"}]})
        self.assertEqual(response["output_text"], "READY")
        self.assertEqual(metadata["server_request_id"], "server-42")
        self.assertEqual(metadata["response_id"], "resp-42")
        self.assertEqual(metadata["token_usage"]["total_tokens"], 5)
        request = urlopen.call_args.args[0]
        self.assertTrue(request.headers.get("X-client-request-id"))

    @patch("gpt56_reasoning_probe.urllib.request.urlopen")
    def test_all_optional_request_metadata_can_be_omitted(self, urlopen):
        urlopen.return_value = _Response(b'{"output_text":"READY"}')
        options = MetadataOptions(
            include_request_id=False,
            include_timestamps=False,
            include_duration=False,
            include_http_status=False,
            include_token_usage=False,
            include_response_size=False,
        )
        client = ResponsesClient("https://api.test/v1", "secret", 3, options)
        _response, metadata = client.post({"input": "hi"})
        self.assertEqual(metadata, {})
        request = urlopen.call_args.args[0]
        self.assertIsNone(request.headers.get("X-client-request-id"))

    @patch("gpt56_juice_probe.time.sleep")
    def test_retry_keeps_metadata_for_each_failed_network_attempt(self, _sleep):
        class RetryingClient:
            calls = 0

            def post(self, _payload):
                self.calls += 1
                if self.calls == 1:
                    raise ProbeError(
                        "temporary",
                        status=503,
                        metadata={"correlation_id": "retry-1", "http_status": 503},
                    )
                return (
                    {"output_text": "40", "id": "resp-success"},
                    {"correlation_id": "retry-2", "response_id": "resp-success"},
                )

        result = run_juice_request(RetryingClient(), "gpt-5.6-sol", "high")
        self.assertEqual(result["transport_attempts"], 2)
        self.assertEqual(
            result["transport_errors"][0]["request_metadata"]["correlation_id"],
            "retry-1",
        )
        self.assertEqual(result["correlation_id"], "retry-2")
        self.assertEqual(len(format_attempt_logs("request", result)), 2)

    def test_html_report_includes_request_metadata(self):
        report = {
            "mode": "juice_only_single_v3_1_1",
            "configuration": {
                "detection_mode": "juice_only",
                "request_metadata": MetadataOptions().report_config(),
            },
            "juice_observations": [
                {
                    "correlation_id": "local-1",
                    "server_request_id": "server-1",
                    "started_at": "2026-08-07T01:02:03+00:00",
                    "http_status": 200,
                    "elapsed_ms": 12,
                    "token_usage": {"source": "provider_usage", "total_tokens": 9},
                }
            ],
        }
        html = render_report_html(report)
        self.assertIn("请求级详细信息", html)
        self.assertIn("server-1", html)
        self.assertIn("usage: 9", html)


if __name__ == "__main__":
    unittest.main()
