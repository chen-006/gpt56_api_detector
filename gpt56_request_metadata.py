"""Privacy-aware request metadata collection for detector reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import ipaddress
import json
import math
import socket
from typing import Any, Mapping
import urllib.request
from urllib.parse import urlsplit


DEFAULT_CLIENT_IP_LOOKUP_URL = "https://api64.ipify.org?format=json"
REQUEST_ID_HEADERS = (
    "x-request-id",
    "request-id",
    "openai-request-id",
    "x-correlation-id",
    "traceparent",
    "cf-ray",
)


@dataclass(frozen=True)
class MetadataOptions:
    """Control which request details are persisted in reports."""

    include_request_id: bool = True
    include_timestamps: bool = True
    include_duration: bool = True
    include_http_status: bool = True
    include_token_usage: bool = True
    include_response_size: bool = True
    include_server_ip: bool = False
    include_client_ip: bool = False
    estimate_tokens: bool = False
    client_ip_lookup_url: str = DEFAULT_CLIENT_IP_LOOKUP_URL

    def report_config(self) -> dict[str, Any]:
        config = asdict(self)
        config["client_ip_lookup_url"] = (
            self.client_ip_lookup_url if self.include_client_ip else None
        )
        config["privacy_note"] = (
            "IP fields are omitted unless explicitly enabled. Client egress IP lookup "
            "uses the configured URL through the process proxy settings."
        )
        config["token_estimate_warning"] = (
            "Estimated token counts are approximate and may differ from provider billing."
            if self.estimate_tokens
            else None
        )
        return config


def add_metadata_arguments(parser: Any) -> None:
    """Add consistent report-metadata options to an argparse parser."""

    parser.add_argument("--omit-request-id", action="store_true")
    parser.add_argument("--omit-timestamps", action="store_true")
    parser.add_argument("--omit-duration", action="store_true")
    parser.add_argument("--omit-http-status", action="store_true")
    parser.add_argument("--omit-token-usage", action="store_true")
    parser.add_argument("--omit-response-size", action="store_true")
    parser.add_argument("--include-server-ip", action="store_true")
    parser.add_argument("--include-client-ip", action="store_true")
    parser.add_argument(
        "--client-ip-lookup-url",
        default=DEFAULT_CLIENT_IP_LOOKUP_URL,
        help=(
            "IP echo endpoint used only with --include-client-ip; the request follows "
            "the process proxy settings so the observed address is the actual egress IP"
        ),
    )
    parser.add_argument(
        "--estimate-tokens",
        action="store_true",
        help=(
            "estimate tokens only when provider usage is absent; estimates are approximate "
            "and are clearly labelled in reports"
        ),
    )


def metadata_options_from_args(args: Any) -> MetadataOptions:
    return MetadataOptions(
        include_request_id=not args.omit_request_id,
        include_timestamps=not args.omit_timestamps,
        include_duration=not args.omit_duration,
        include_http_status=not args.omit_http_status,
        include_token_usage=not args.omit_token_usage,
        include_response_size=not args.omit_response_size,
        include_server_ip=args.include_server_ip,
        include_client_ip=args.include_client_ip,
        estimate_tokens=args.estimate_tokens,
        client_ip_lookup_url=args.client_ip_lookup_url,
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def resolve_server_ips(url: str) -> list[str]:
    """Resolve the target hostname; these are DNS results, not proxy peer addresses."""

    hostname = urlsplit(url).hostname
    if not hostname:
        return []
    try:
        return [str(ipaddress.ip_address(hostname))]
    except ValueError:
        pass
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
    except OSError:
        return []
    return sorted(addresses, key=lambda value: (":" in value, value))


def lookup_client_egress_ip(url: str, timeout: float = 10.0) -> str:
    """Query an IP echo service using urllib's normal proxy-aware transport."""

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, text/plain",
            "User-Agent": "gpt56-detector/metadata",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(4096).decode("utf-8").strip()
    candidate = raw
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError:
        decoded = None
    if isinstance(decoded, dict):
        candidate = str(
            decoded.get("ip") or decoded.get("origin") or decoded.get("query") or ""
        ).split(",", 1)[0].strip()
    return str(ipaddress.ip_address(candidate))


def extract_request_id(headers: Mapping[str, str]) -> tuple[str | None, str | None]:
    normalized = {str(key).casefold(): str(value) for key, value in headers.items()}
    for name in REQUEST_ID_HEADERS:
        value = normalized.get(name)
        if value:
            return value, name
    return None, None


def extract_usage(response: Mapping[str, Any]) -> dict[str, Any] | None:
    usage = response.get("usage")
    if not isinstance(usage, Mapping):
        return None
    input_tokens = usage.get("input_tokens", usage.get("prompt_tokens"))
    output_tokens = usage.get("output_tokens", usage.get("completion_tokens"))
    total_tokens = usage.get("total_tokens")
    result = {
        "source": "provider_usage",
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }
    details = {
        key: value
        for key, value in usage.items()
        if key
        not in {
            "input_tokens",
            "prompt_tokens",
            "output_tokens",
            "completion_tokens",
            "total_tokens",
        }
    }
    if details:
        result["details"] = details
    return result


def _text_length(value: Any) -> int:
    if isinstance(value, str):
        return len(value)
    if isinstance(value, Mapping):
        if "content" in value:
            return _text_length(value["content"])
        ignored = {"role", "type", "id", "status"}
        return sum(
            _text_length(item) for key, item in value.items() if key not in ignored
        )
    if isinstance(value, (list, tuple)):
        return sum(_text_length(item) for item in value)
    return 0


def estimate_usage(payload: Mapping[str, Any], response: Mapping[str, Any]) -> dict[str, Any]:
    """Provide a deliberately labelled fallback when provider usage is unavailable."""

    input_chars = _text_length(payload.get("input"))
    output_chars = _text_length(response.get("output_text")) or _text_length(
        response.get("output")
    )
    input_tokens = math.ceil(input_chars / 4) if input_chars else 0
    output_tokens = math.ceil(output_chars / 4) if output_chars else 0
    return {
        "source": "estimated",
        "method": "unicode_characters_divided_by_4",
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": input_tokens + output_tokens,
        "warning": "Approximate only; tokenizer and provider billing may differ.",
    }


def build_request_metadata(
    *,
    options: MetadataOptions,
    correlation_id: str,
    url: str,
    payload: Mapping[str, Any],
    response: Mapping[str, Any],
    response_headers: Mapping[str, str],
    status: int | None,
    started_at: datetime,
    completed_at: datetime,
    elapsed_ms: int,
    response_size_bytes: int,
    server_ips: list[str] | None = None,
    client_ip: str | None = None,
    client_ip_error: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if options.include_request_id:
        request_id, request_id_header = extract_request_id(response_headers)
        metadata.update(
            {
                "correlation_id": correlation_id,
                "server_request_id": request_id,
                "server_request_id_header": request_id_header,
                "response_id": (
                    response.get("id") if isinstance(response.get("id"), str) else None
                ),
            }
        )
    if options.include_timestamps:
        metadata["started_at"] = started_at.isoformat()
        metadata["completed_at"] = completed_at.isoformat()
    if options.include_duration:
        metadata["elapsed_ms"] = elapsed_ms
    if options.include_http_status:
        metadata["http_status"] = status
    if options.include_response_size:
        metadata["response_size_bytes"] = response_size_bytes
    if options.include_token_usage:
        usage = extract_usage(response)
        if usage is None and options.estimate_tokens:
            usage = estimate_usage(payload, response)
        metadata["token_usage"] = usage
    if options.include_server_ip:
        metadata["server_ips"] = (
            server_ips if server_ips is not None else resolve_server_ips(url)
        )
        metadata["server_ip_source"] = "target_hostname_dns_resolution"
        metadata["server_ip_note"] = (
            "These are target DNS results; when an HTTP proxy is used they are not the proxy peer IP."
        )
    if options.include_client_ip:
        metadata["client_egress_ip"] = client_ip
        metadata["client_ip_source"] = options.client_ip_lookup_url
        if client_ip_error:
            metadata["client_ip_error"] = client_ip_error
    return metadata


def format_metadata_log(metadata: Mapping[str, Any]) -> str:
    """Render enabled metadata as a compact console-log suffix."""

    parts: list[str] = []
    request_id = (
        metadata.get("server_request_id")
        or metadata.get("response_id")
        or metadata.get("correlation_id")
    )
    if request_id:
        parts.append(f"request_id={request_id}")
    if metadata.get("started_at"):
        parts.append(f"time={metadata['started_at']}")
    if "http_status" in metadata:
        parts.append(f"http={metadata['http_status']}")
    if "elapsed_ms" in metadata:
        parts.append(f"elapsed_ms={metadata['elapsed_ms']}")
    usage = metadata.get("token_usage")
    if isinstance(usage, Mapping):
        label = "estimated_tokens" if usage.get("source") == "estimated" else "tokens"
        parts.append(f"{label}={usage.get('total_tokens')}")
    if "response_size_bytes" in metadata:
        parts.append(f"bytes={metadata['response_size_bytes']}")
    if metadata.get("server_ips"):
        parts.append(f"server_ip={metadata['server_ips'][0]}")
    if metadata.get("client_egress_ip"):
        parts.append(f"client_egress_ip={metadata['client_egress_ip']}")
    return f" [{', '.join(parts)}]" if parts else ""


def format_attempt_logs(label: str, result: Mapping[str, Any]) -> list[str]:
    """Include retry attempts as separate lines before the final request."""

    lines: list[str] = []
    errors = result.get("transport_errors", [])
    if isinstance(errors, list):
        for index, error in enumerate(errors, start=1):
            if not isinstance(error, Mapping):
                continue
            metadata = error.get("request_metadata", {})
            suffix = format_metadata_log(metadata) if isinstance(metadata, Mapping) else ""
            if suffix:
                lines.append(f"{label} retry {index}{suffix}")
    suffix = format_metadata_log(result)
    if suffix:
        lines.append(f"{label}{suffix}")
    return lines
