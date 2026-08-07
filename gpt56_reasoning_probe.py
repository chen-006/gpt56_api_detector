#!/usr/bin/env python3
"""Probe GPT-5.6 encrypted-reasoning compatibility across two Responses APIs.

This is a capability test, not cryptographic proof of model identity. A passing
candidate can decrypt/replay state emitted by the trusted GPT-5.6 endpoint, or
can proxy the request to a backend that can. It cannot distinguish Sol, Terra,
and Luna.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from gpt56_juice_probe import (
    EFFORTS,
    EFFORT_LABELS_CN,
    JUICE_HIGH_WINDOW,
    JUICE_OTHER_WINDOW,
    MODEL_LABELS_CN,
    OUTPUT_LITERAL_CONTROL_WINDOW,
    OUTPUT_LITERAL_CONTROL_VALUES,
    classify_visible_answer,
    combined_summary,
    format_juice_effort_stats_cn,
    juice_connection_quality,
    juice_only_summary,
    matching_models,
    run_output_literal_control,
    run_juice_request,
    summarize_output_literal_controls,
    summarize_juice,
)
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from gpt56_report_html import write_report_html
from gpt56_request_metadata import (
    MetadataOptions,
    add_metadata_arguments,
    build_request_metadata,
    lookup_client_egress_ip,
    format_metadata_log,
    format_attempt_logs,
    metadata_options_from_args,
    resolve_server_ips,
    utc_now,
)


TASKS = (
    (
        "reverse",
        "In hidden reasoning, take the ten-digit input {value} and compute B by reversing all ten digits. "
        "Retain the exact ten-digit B for the next turn. Do not expose the input, B, intermediate work, "
        "or any hint in visible output. Your entire visible response must be exactly READY",
    ),
    (
        "rotate_left_3",
        "In hidden reasoning, take the ten-digit input {value} and compute B by moving its first three "
        "digits to the end without changing any other order. Retain the exact ten-digit B for the next "
        "turn. Reveal no digits or work. Your complete visible response must be exactly READY",
    ),
    (
        "complement_9",
        "In hidden reasoning, transform the ten-digit input {value} digit by digit using d -> 9-d and "
        "call the resulting ten-character digit string B. Retain B for the next turn. Do not reveal any "
        "input, result, or work. Your entire visible response must be exactly READY",
    ),
)

RECALL_PROMPT = (
    "Return the exact ten-digit value B computed and retained in the preceding hidden reasoning state. "
    "Output only B. If that state is absent or unreadable, output exactly UNKNOWN. Do not recompute, "
    "guess, or create a replacement value."
)

KEY_PATTERN = re.compile(r"sk-[A-Za-z0-9_-]{12,}")
TRANSIENT_HTTP_STATUSES = {429, 500, 502, 503, 504}


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def redact(value: Any, key: str | None = None) -> Any:
    if key == "encrypted_content" and isinstance(value, str):
        return {"redacted": True, "length": len(value), "sha256": sha256(value)}
    if isinstance(value, dict):
        return {
            child_key: (
                "[REDACTED]"
                if child_key.lower() in {"authorization", "api_key", "apikey"}
                else redact(child_value, child_key)
            )
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return KEY_PATTERN.sub("sk-[REDACTED]", value)
    return value


def output_text(response: dict[str, Any]) -> str:
    direct = response.get("output_text")
    if isinstance(direct, str):
        return direct.strip()
    chunks: list[str] = []
    for item in response.get("output", []):
        if not isinstance(item, dict) or item.get("type") != "message":
            continue
        for part in item.get("content", []):
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                chunks.append(part["text"])
    return "".join(chunks).strip()


def random_ten_digits() -> str:
    first = str(secrets.randbelow(9) + 1)
    middle = "".join(str(secrets.randbelow(10)) for _ in range(8))
    last = str(secrets.randbelow(9) + 1)
    return first + middle + last


def random_float(minimum: float, maximum: float) -> float:
    if maximum <= minimum:
        return minimum
    return minimum + (maximum - minimum) * (secrets.randbelow(1_000_001) / 1_000_000)


def transform(task: str, value: str) -> str:
    if task == "reverse":
        return value[::-1]
    if task == "rotate_left_3":
        return value[3:] + value[:3]
    if task == "complement_9":
        return "".join(str(9 - int(char)) for char in value)
    raise ValueError(f"unknown task: {task}")


class ProbeError(RuntimeError):
    def __init__(
        self,
        message: str,
        status: int | None = None,
        elapsed_ms: int | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.elapsed_ms = elapsed_ms
        self.metadata = metadata or {}


@dataclass
class ResponsesClient:
    base_url: str
    api_key: str
    timeout: float
    metadata_options: MetadataOptions = field(default_factory=MetadataOptions)
    _server_ips: list[str] = field(default_factory=list, init=False, repr=False)
    _server_ips_loaded: bool = field(default=False, init=False, repr=False)
    _client_ip: str | None = field(default=None, init=False, repr=False)
    _client_ip_error: str | None = field(default=None, init=False, repr=False)
    _client_ip_loaded: bool = field(default=False, init=False, repr=False)
    _metadata_cache_lock: Lock = field(default_factory=Lock, init=False, repr=False)

    @property
    def url(self) -> str:
        return self.base_url.rstrip("/") + "/responses"

    def _network_addresses(self) -> tuple[list[str], str | None, str | None]:
        with self._metadata_cache_lock:
            if self.metadata_options.include_server_ip and not self._server_ips_loaded:
                self._server_ips = resolve_server_ips(self.url)
                self._server_ips_loaded = True
            if self.metadata_options.include_client_ip and not self._client_ip_loaded:
                self._client_ip_loaded = True
                try:
                    self._client_ip = lookup_client_egress_ip(
                        self.metadata_options.client_ip_lookup_url,
                        timeout=min(max(self.timeout, 1.0), 10.0),
                    )
                except (OSError, ValueError) as exc:
                    self._client_ip_error = type(exc).__name__
        return self._server_ips, self._client_ip, self._client_ip_error

    def _metadata(
        self,
        *,
        correlation_id: str,
        payload: dict[str, Any],
        decoded: dict[str, Any],
        response_headers: dict[str, str],
        status: int | None,
        started_at: datetime,
        elapsed_ms: int,
        response_size_bytes: int,
    ) -> dict[str, Any]:
        completed_at = utc_now()
        server_ips, client_ip, client_ip_error = self._network_addresses()
        return build_request_metadata(
            options=self.metadata_options,
            correlation_id=correlation_id,
            url=self.url,
            payload=payload,
            response=decoded,
            response_headers=response_headers,
            status=status,
            started_at=started_at,
            completed_at=completed_at,
            elapsed_ms=elapsed_ms,
            response_size_bytes=response_size_bytes,
            server_ips=server_ips,
            client_ip=client_ip,
            client_ip_error=client_ip_error,
        )

    def post(self, payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        correlation_id = uuid.uuid4().hex
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": os.environ.get("GPT56_USER_AGENT", "python-urllib/3"),
        }
        if self.metadata_options.include_request_id:
            headers["X-Client-Request-ID"] = correlation_id
        request = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers=headers,
        )
        started_at = utc_now()
        started = time.perf_counter()
        status: int | None = None
        raw = b""
        response_headers: dict[str, str] = {}
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = response.status
                response_headers = dict(response.headers.items())
                raw = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            raw = exc.read()
        except Exception as exc:
            elapsed = round((time.perf_counter() - started) * 1000)
            metadata = self._metadata(
                correlation_id=correlation_id,
                payload=payload,
                decoded={},
                response_headers=response_headers,
                status=None,
                started_at=started_at,
                elapsed_ms=elapsed,
                response_size_bytes=0,
            )
            raise ProbeError(
                redact(str(exc)), status=None, elapsed_ms=elapsed, metadata=metadata
            ) from exc
        elapsed = round((time.perf_counter() - started) * 1000)
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            metadata = self._metadata(
                correlation_id=correlation_id,
                payload=payload,
                decoded={},
                response_headers=response_headers,
                status=status,
                started_at=started_at,
                elapsed_ms=elapsed,
                response_size_bytes=len(raw),
            )
            raise ProbeError(
                "non-JSON response", status=status, elapsed_ms=elapsed, metadata=metadata
            ) from exc
        metadata = self._metadata(
            correlation_id=correlation_id,
            payload=payload,
            decoded=decoded if isinstance(decoded, dict) else {},
            response_headers=response_headers,
            status=status,
            started_at=started_at,
            elapsed_ms=elapsed,
            response_size_bytes=len(raw),
        )
        if status is None or not 200 <= status < 300:
            error = decoded.get("error", decoded) if isinstance(decoded, dict) else decoded
            raise ProbeError(
                str(redact(error)), status=status, elapsed_ms=elapsed, metadata=metadata
            )
        if not isinstance(decoded, dict):
            raise ProbeError(
                "response JSON is not an object",
                status=status,
                elapsed_ms=elapsed,
                metadata=metadata,
            )
        return decoded, metadata


def seed_payload(model: str, prompt: str) -> dict[str, Any]:
    return {
        "model": model,
        "input": [{"role": "user", "content": prompt}],
        "reasoning": {"effort": "high"},
        "include": ["reasoning.encrypted_content"],
        "store": False,
    }


def recall_payload(model: str, context: list[Any]) -> dict[str, Any]:
    return {
        "model": model,
        "input": copy.deepcopy(context) + [{"role": "user", "content": RECALL_PROMPT}],
        "reasoning": {"effort": "high"},
        "include": ["reasoning.encrypted_content"],
        "store": False,
    }


def select_items(output: list[Any], item_type: str) -> list[dict[str, Any]]:
    return [
        copy.deepcopy(item)
        for item in output
        if isinstance(item, dict) and item.get("type") == item_type
    ]


def context_variant(output: list[Any], variant: str) -> list[Any]:
    if variant == "full":
        return copy.deepcopy(output)
    if variant == "message_only":
        return select_items(output, "message")
    context = copy.deepcopy(output)
    if variant == "without_ids":
        for item in context:
            if isinstance(item, dict):
                item.pop("id", None)
        return context
    if variant == "corrupted_ciphertext":
        changed = False
        for item in context:
            if not isinstance(item, dict) or item.get("type") != "reasoning":
                continue
            encrypted = item.get("encrypted_content")
            if isinstance(encrypted, str) and encrypted:
                index = len(encrypted) // 2
                replacement = "A" if encrypted[index] != "A" else "B"
                item["encrypted_content"] = encrypted[:index] + replacement + encrypted[index + 1 :]
                changed = True
        if not changed:
            raise ValueError("no encrypted reasoning item to corrupt")
        return context
    raise ValueError(f"unknown context variant: {variant}")


def encrypted_fingerprints(output: list[Any]) -> list[dict[str, Any]]:
    fingerprints = []
    for item in output:
        if not isinstance(item, dict) or item.get("type") != "reasoning":
            continue
        encrypted = item.get("encrypted_content")
        if isinstance(encrypted, str) and encrypted:
            fingerprints.append({"length": len(encrypted), "sha256": sha256(encrypted)})
    return fingerprints


def call_and_score(
    client: ResponsesClient,
    model: str,
    context: list[Any],
    expected: str,
    *,
    max_transport_attempts: int = 1,
    retry_base_seconds: float = 2.0,
) -> dict[str, Any]:
    payload = recall_payload(model, context)
    serialized = json.dumps(redact(payload), ensure_ascii=False)
    plaintext_leak = expected in serialized
    if plaintext_leak:
        return {
            "status": "invalid_probe",
            "exact": False,
            "plaintext_leak": True,
            "error": "expected value appeared in candidate request plaintext",
        }

    last_error: ProbeError | None = None
    transport_errors: list[dict[str, Any]] = []
    for transport_attempt in range(1, max_transport_attempts + 1):
        try:
            response, meta = client.post(payload)
            answer = output_text(response)
            return {
                "status": "ok",
                "exact": answer == expected,
                "unknown": answer == "UNKNOWN",
                "answer_sha256": sha256(answer),
                "answer_length": len(answer),
                "plaintext_leak": False,
                "transport_attempts": transport_attempt,
                "transport_errors": transport_errors,
                **meta,
            }
        except ProbeError as exc:
            last_error = exc
            error_event = {
                "error": redact(str(exc)),
                "request_metadata": exc.metadata,
            }
            if "http_status" in exc.metadata:
                error_event["http_status"] = exc.metadata["http_status"]
            if "elapsed_ms" in exc.metadata:
                error_event["elapsed_ms"] = exc.metadata["elapsed_ms"]
            transport_errors.append(error_event)
            transient = exc.status is None or exc.status in TRANSIENT_HTTP_STATUSES
            if transport_attempt >= max_transport_attempts or not transient:
                break
            backoff = retry_base_seconds * (2 ** (transport_attempt - 1))
            time.sleep(backoff + secrets.randbelow(1001) / 1000)

    assert last_error is not None
    return {
        "status": "error",
        "exact": False,
        "plaintext_leak": False,
        "transport_attempts": transport_attempt,
        "transport_errors": transport_errors,
        "error": redact(str(last_error)),
        **last_error.metadata,
    }

def blind_guess_tail_probability(successes: int, trials: int) -> float:
    if successes <= 0:
        return 1.0
    p = 1e-10
    return sum(
        math.comb(trials, count) * (p**count) * ((1 - p) ** (trials - count))
        for count in range(successes, trials + 1)
    )

def encrypted_state_verdict(
    *,
    attempts: int,
    required_attempts: int,
    full_exact: int,
    without_ids_exact: int,
    required_matches: int,
    message_only_exact: int,
    corrupted_ciphertext_exact: int,
    plaintext_leaks: int,
    warming_verdict: str = "inconclusive",
    incompatible_verdict: str = "not_compatible_in_this_probe",
) -> tuple[str, str]:
    """Judge model capability independently from transport quality."""
    if attempts < required_attempts:
        return warming_verdict, "not enough candidate attempts"
    if plaintext_leaks:
        return "invalid", "one or more candidate requests contained challenge plaintext"
    if message_only_exact or corrupted_ciphertext_exact:
        return "suspicious", "a negative control unexpectedly matched the hidden challenge"
    if full_exact >= required_matches and without_ids_exact >= required_matches:
        return (
            "gpt_5_6_encrypted_state_compatible",
            "candidate repeatedly recovered trusted GPT-5.6 hidden values from encrypted state",
        )
    if full_exact == 0 and without_ids_exact == 0:
        return incompatible_verdict, "candidate recovered none of the trusted encrypted challenge states"
    return "inconclusive", "partial replay evidence did not reach the configured threshold"


def connection_quality(error_rounds: int, retry_rounds: int) -> dict[str, Any]:
    if error_rounds:
        return {
            "status": "unstable",
            "title_cn": "不稳定",
            "detail_cn": f"{error_rounds} 轮最终失败，{retry_rounds} 轮发生过重试",
        }
    if retry_rounds:
        return {
            "status": "intermittent",
            "title_cn": "偶有波动",
            "detail_cn": f"没有最终失败，{retry_rounds} 轮重试后恢复",
        }
    return {
        "status": "smooth",
        "title_cn": "流畅",
        "detail_cn": "没有最终失败，也没有发生重试",
    }

TASK_LABELS_CN = {
    "reverse": "十位数字倒序",
    "rotate_left_3": "前三位移到末尾",
    "complement_9": "逐位计算九补数",
}

VERDICT_LABELS_CN = {
    "gpt_5_6_encrypted_state_compatible": ("检测通过", "是"),
    "not_compatible_in_this_probe": ("当前检测未观察到兼容能力", "否"),
    "inconclusive": ("证据不足或网络不稳定", "尚不能确认"),
    "suspicious": ("阴性对照异常，结果不可信", "否"),
    "invalid": ("检测发生明文泄漏，结果无效", "否"),
}


def print_candidate_attempt_result(trial: dict[str, Any]) -> None:
    candidate = trial["candidate"]
    retries = sum(
        len(result.get("transport_errors", [])) for result in candidate.values()
    )
    errors = sum(result.get("status") == "error" for result in candidate.values())
    negative = int(bool(candidate["message_only"].get("exact"))) + int(
        bool(candidate["corrupted_ciphertext"].get("exact"))
    )
    network = "正常" if not errors and not retries else f"失败 {errors} 个，重试 {retries} 次"
    print(
        "本轮结果："
        f"完整状态{'答对' if candidate['full'].get('exact') else '未答对'}，"
        f"去掉编号后{'答对' if candidate['without_ids'].get('exact') else '未答对'}，"
        f"异常测试{'正常' if negative == 0 else '命中'}，线路{network}"
    )
    for variant, result in candidate.items():
        for line in format_attempt_logs(variant, result):
            print(f"  {line}")
    trusted_seed = trial.get("trusted_seed", {}).get("request_metadata", {})
    if trusted_seed:
        print(f"  trusted seed{format_metadata_log(trusted_seed)}")
    for line in format_attempt_logs("trusted self", trial.get("trusted_self", {})):
        print(f"  {line}")


def print_probe_summary(report: dict[str, Any], report_path: Path) -> None:
    summary = report["summary"]
    verdict = report["verdict"]
    combined = report["combined_summary"]
    juice = report.get("juice_summary")
    requested = report["configuration"]["requested_candidate_attempts"]
    attempts = summary["candidate_attempts"]
    required = report["configuration"]["required_matches_per_positive_condition"]
    negative = (
        summary["candidate_message_only_exact"]
        + summary["candidate_corrupted_ciphertext_exact"]
    )
    network = report["network_summary"]
    juice_only = report["configuration"].get("detection_mode") == "juice_only"
    confidence_cn = {
        "high": "高", "medium": "中", "preliminary": "初步", "insufficient": "不足"
    }

    print("\n" + "=" * 62)
    print(f"检测完成：{combined['title_cn']}（是否通过：{combined['passed_cn']}）")
    print(f"综合结论：{combined['explanation_cn']}")
    if juice_only:
        strong_text = "未检测（本次仅运行 Juice 辅助指纹）"
    elif verdict == "gpt_5_6_encrypted_state_compatible":
        strong_text = "通过，极高置信度具备 GPT-5.6 加密状态处理能力"
    else:
        strong_text = VERDICT_LABELS_CN.get(verdict, (verdict, ""))[0]
    if juice_only:
        print(f"模型能力：{strong_text}")
    else:
        print(
            f"模型能力：{strong_text}；"
            f"两种有效测试 {summary['candidate_full_exact']}/{required}、"
            f"{summary['candidate_without_ids_exact']}/{required}"
        )
        print(
            f"防误判检查：异常命中 {negative}，答案泄漏 "
            f"{summary['candidate_request_plaintext_leaks']}（都必须为 0）"
        )
    if juice is not None:
        mixed_cn = "已发现" if juice["status"] == "mixed_or_inconsistent" else "未发现"
        high_stats = juice["effort_stats"]["high"]
        print(
            f"具体型号：{juice['likely_model_cn']}（置信度"
            f"{confidence_cn.get(juice['confidence'], juice['confidence'])}，"
            f"高档窗口 {high_stats['observations']}/{high_stats['window_limit']}，"
            f"有效数字 {high_stats['numeric_samples']}，"
            f"混用{mixed_cn}）"
        )
        print("分档统计：" + format_juice_effort_stats_cn(juice))
        if juice["status"] == "mixed_or_inconsistent":
            labels = [
                MODEL_LABELS_CN.get(item, item)
                for item in juice["session_distinct_high_groups"]
            ]
            conflicts = juice.get("session_conflicting_observations", [])
            if len(labels) >= 2:
                detail = f"高档同时出现：{'、'.join(labels)}"
            elif conflicts:
                detail = "与主要型号冲突：" + "、".join(
                    f"{EFFORT_LABELS_CN.get(item['effort'], item['effort'])}档={item['normalized_value']}"
                    for item in conflicts
                )
            else:
                detail = "型号结果互相冲突"
            print(f"严重警报：{detail}。已直接标记混用。")
    output_control = report.get("output_literal_control_summary")
    if output_control is not None:
        print(
            f"高档字面量对照：{output_control['title_cn']}（窗口 "
            f"{output_control['observations_in_window']}/{output_control['window_size']}，"
            f"精确 {output_control['exact_expected']}，"
            f"非预期 {output_control['non_exact_successes']}，"
            f"错误 {output_control['errors']}，"
            f"会话异常 {output_control['session_non_exact_successes']}；"
            f"48 {output_control['exact_by_expected']['48']}/"
            f"{output_control['expected_counts']['48']}，"
            f"32 {output_control['exact_by_expected']['32']}/"
            f"{output_control['expected_counts']['32']}）"
        )
        if output_control["status"] == "output_rewrite_suspected":
            latest = output_control["session_anomalies"][-1]
            print(
                "严重警报：高档字面量对照返回非预期内容："
                f"要求 {latest.get('expected_text')!r}，"
                f"得到 {latest.get('observed_text')!r}。本会话持续保留。"
            )
    print(f"线路情况：{network['title_cn']}（{network['detail_cn']}）")
    if juice_only:
        print(f"Juice 请求：{len(report['juice_observations'])} 次")
    else:
        print(
            f"样本：{attempts}/{requested} 轮；"
            f"可信端自行验证失败 {summary['rejected_trusted_attempts']} 次"
        )
    print(f"详细脱敏报告：{report_path.resolve()}")
    print("=" * 62)


def shuffled_juice_jobs(repeats: int) -> list[str]:
    jobs = [effort for effort in EFFORTS for _ in range(repeats)]
    for index in range(len(jobs) - 1, 0, -1):
        other = secrets.randbelow(index + 1)
        jobs[index], jobs[other] = jobs[other], jobs[index]
    return jobs


def run_juice_batch(
    args: argparse.Namespace,
    candidate: ResponsesClient,
) -> list[dict[str, Any]]:
    jobs = shuffled_juice_jobs(args.juice_repeats)
    observations: list[dict[str, Any]] = []
    print("\n" + "=" * 66)
    print("开始 Juice 浅层型号指纹")
    print(
        f"五档各测 {args.juice_repeats} 次；汇总窗口为高档 {JUICE_HIGH_WINDOW}、"
        f"其他档位各 {JUICE_OTHER_WINDOW}。"
    )
    print("=" * 66, flush=True)
    def run_job(index: int, effort: str) -> tuple[int, dict[str, Any]]:
        print(
            f"浅层指纹 {index}/{len(jobs)}：{EFFORT_LABELS_CN[effort]}档……",
            flush=True,
        )
        observation = run_juice_request(
            candidate,
            args.candidate_model,
            effort,
            max_transport_attempts=args.candidate_retries + 1,
        )
        if observation["answer_kind"] == "number":
            detail = f"数字 {observation['normalized_value']}"
        elif observation["answer_kind"] == "refusal":
            detail = "模型拒绝提供（记为无证据）"
        elif observation["answer_kind"] == "error":
            detail = "接口错误（记为无证据）"
        else:
            detail = "其他非数字回复（记为无证据）"
        print(f"  {index}/{len(jobs)} 结果：{detail}", flush=True)
        for line in format_attempt_logs("request", observation):
            print(f"    {line}", flush=True)
        return index, observation

    workers = min(args.workers, len(jobs))
    if workers == 1:
        for index, effort in enumerate(jobs, start=1):
            _, observation = run_job(index, effort)
            observations.append(observation)
            if index < len(jobs):
                time.sleep(random_float(args.candidate_min_gap, args.candidate_max_gap))
        return observations

    completed: dict[int, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(run_job, index, effort): index
            for index, effort in enumerate(jobs, start=1)
        }
        for future in as_completed(futures):
            index, observation = future.result()
            completed[index] = observation
    return [completed[index] for index in range(1, len(jobs) + 1)]


def run_output_literal_control_once(
    args: argparse.Namespace,
    candidate: ResponsesClient,
) -> dict[str, Any]:
    print("正在进行高档字面量输出完整性对照……", flush=True)
    observation = run_output_literal_control(
        candidate,
        args.candidate_model,
        max_transport_attempts=args.candidate_retries + 1,
    )
    if observation["status"] == "error":
        detail = "接口错误"
    elif observation["exact_output"]:
        detail = f"精确返回 {observation['expected_text']}"
    else:
        detail = (
            f"要求 {observation['expected_text']}，"
            f"返回 {observation.get('observed_text')!r}"
        )
    print(f"  结果：{detail}", flush=True)
    for line in format_attempt_logs("request", observation):
        print(f"  {line}", flush=True)
    return observation


def run_single_output_literal_controls(
    args: argparse.Namespace,
    candidate: ResponsesClient,
) -> list[dict[str, Any]]:
    """Run one fixed high-effort control for each Luna and Terra literal."""
    observations: list[dict[str, Any]] = []
    for expected_text in OUTPUT_LITERAL_CONTROL_VALUES:
        print(f"正在进行高档字面量输出完整性对照：{expected_text}……", flush=True)
        observation = run_output_literal_control(
            candidate,
            args.candidate_model,
            expected_text=expected_text,
            max_transport_attempts=args.candidate_retries + 1,
        )
        observations.append(observation)
        if observation["status"] == "error":
            detail = "接口错误"
        elif observation["exact_output"]:
            detail = f"精确返回 {expected_text}"
        else:
            detail = f"返回 {observation.get('observed_text')!r}"
        print(f"  结果：{detail}", flush=True)
        for line in format_attempt_logs("request", observation):
            print(f"  {line}", flush=True)
    return observations


def run_juice_only_probe(
    args: argparse.Namespace,
    candidate: ResponsesClient,
) -> dict[str, Any]:
    observations = run_juice_batch(args, candidate)
    time.sleep(random_float(args.candidate_min_gap, args.candidate_max_gap))
    output_literal_controls = run_single_output_literal_controls(args, candidate)
    output_literal_summary = summarize_output_literal_controls(
        output_literal_controls
    )
    juice_summary = summarize_juice(observations)
    network_summary = juice_connection_quality(observations)
    combined = juice_only_summary(
        juice_summary, args.candidate_model, network_summary
    )
    combined["output_literal_control_status"] = output_literal_summary["status"]
    empty_summary = {
        "candidate_attempts": 0,
        "complete_trials": 0,
        "valid_trials": 0,
        "rejected_trusted_attempts": 0,
        "candidate_full_exact": 0,
        "candidate_without_ids_exact": 0,
        "candidate_message_only_exact": 0,
        "candidate_corrupted_ciphertext_exact": 0,
        "candidate_request_plaintext_leaks": 0,
        "candidate_request_errors": 0,
        "candidate_error_rounds": 0,
        "candidate_retry_rounds": 0,
        "blind_guess_upper_tail_full": None,
        "blind_guess_upper_tail_without_ids": None,
    }
    return {
        "schema_version": 6,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": "juice_only_single_v3_1_1",
        "verdict": "not_run_juice_only",
        "encrypted_state_verdict": "not_run_juice_only",
        "combined_verdict": combined["status"],
        "reason": "Encrypted-state capability layer was intentionally skipped.",
        "scope": (
            "Juice visible-output fingerprint only. This mode does not test encrypted "
            "reasoning-state compatibility or prove backend identity."
        ),
        "configuration": {
            "request_metadata": args.metadata_options.report_config(),
            "detection_mode": "juice_only",
            "candidate_base_url": args.candidate_base_url,
            "candidate_model": args.candidate_model,
            "requested_candidate_attempts": 0,
            "requested_valid_trials": 0,
            "required_matches_per_positive_condition": 0,
            "candidate_transient_retries": args.candidate_retries,
            "candidate_request_gap_seconds": [
                args.candidate_min_gap, args.candidate_max_gap
            ],
            "single_request_workers": args.workers,
            "single_concurrency_scope": "juice_requests",
            "juice_probe_enabled": True,
            "juice_only": True,
            "juice_repeats_per_effort": args.juice_repeats,
            "juice_high_window": JUICE_HIGH_WINDOW,
            "juice_other_window": JUICE_OTHER_WINDOW,
            "output_literal_control_enabled": True,
            "output_literal_control_values": ["48", "32"],
            "output_literal_control_value_probability": 0.5,
            "output_literal_control_single_requests": len(OUTPUT_LITERAL_CONTROL_VALUES),
            "output_literal_control_window": OUTPUT_LITERAL_CONTROL_WINDOW,
            "juice_high_mixing_zero_tolerance": True,
            "juice_mixing_flag_scope": "entire_run",
            "keys_persisted": False,
            "raw_ciphertext_persisted": False,
        },
        "summary": empty_summary,
        "network_summary": network_summary,
        "juice_summary": juice_summary,
        "output_literal_control_summary": output_literal_summary,
        "combined_summary": combined,
        "juice_observations": observations,
        "output_literal_control_observations": output_literal_controls,
        "candidate_attempts": [],
        "valid_trials": [],
        "rejected_attempts": [],
        "limitations": [
            "Juice is an auxiliary visible-output fingerprint and can be spoofed.",
            "This mode does not test encrypted-state capability.",
            "A relay can recognize probe traffic or route it differently.",
        ],
    }


def run_encrypted_attempt(
    args: argparse.Namespace,
    trusted: ResponsesClient,
    candidate: ResponsesClient,
    attempt: int,
    *,
    concurrent_batch: bool,
) -> tuple[int, dict[str, Any] | None, dict[str, Any] | None]:
    task, template = TASKS[(attempt - 1) % len(TASKS)]
    input_value = random_ten_digits()
    expected = transform(task, input_value)
    print(
        f"\nCOT 任务 {attempt}：{TASK_LABELS_CN.get(task, task)}",
        flush=True,
    )
    try:
        seed, seed_meta = trusted.post(
            seed_payload(args.trusted_model, template.format(value=input_value))
        )
    except ProbeError as exc:
        rejection = {
            "attempt": attempt,
            "reason": "trusted_seed_error",
            "http_status": exc.status,
            "error": redact(str(exc)),
            "request_metadata": exc.metadata,
        }
        print(f"COT 任务 {attempt} 舍弃：可信 API 生成状态失败。", flush=True)
        return attempt, None, rejection

    output = seed.get("output")
    visible = output_text(seed)
    if not isinstance(output, list):
        rejection = {"attempt": attempt, "reason": "missing_output_array"}
        print(f"COT 任务 {attempt} 舍弃：可信 API 返回格式不完整。", flush=True)
        return attempt, None, rejection
    fingerprints = encrypted_fingerprints(output)
    sanitized_output = json.dumps(redact(output), ensure_ascii=False)
    visible_leak = input_value in sanitized_output or expected in sanitized_output
    if visible != "READY" or not fingerprints or visible_leak:
        rejection = {
            "attempt": attempt,
            "reason": "invalid_trusted_seed",
            "visible_contract_ok": visible == "READY",
            "encrypted_reasoning_items": len(fingerprints),
            "visible_plaintext_leak": visible_leak,
        }
        print(
            f"COT 任务 {attempt} 舍弃：可信状态不符合 READY、密文或无泄漏要求。",
            flush=True,
        )
        return attempt, None, rejection

    trusted_self = call_and_score(
        trusted,
        args.trusted_model,
        context_variant(output, "full"),
        expected,
    )
    if not trusted_self["exact"]:
        rejection = {
            "attempt": attempt,
            "reason": "trusted_state_not_self_verifiable",
            "trusted_self": trusted_self,
        }
        print(f"COT 任务 {attempt} 舍弃：可信 API 无法自证状态。", flush=True)
        return attempt, None, rejection

    conditions: dict[str, dict[str, Any]] = {}
    variants = ("full", "without_ids", "message_only", "corrupted_ciphertext")
    for index, variant in enumerate(variants):
        conditions[variant] = call_and_score(
            candidate,
            args.candidate_model,
            context_variant(output, variant),
            expected,
            max_transport_attempts=args.candidate_retries + 1,
        )
        if not concurrent_batch and index + 1 < len(variants):
            time.sleep(random_float(args.candidate_min_gap, args.candidate_max_gap))

    trial = {
        "attempt": attempt,
        "task": task,
        "expected_sha256": sha256(expected),
        "trusted_seed": {
            "request_metadata": seed_meta,
            "output_item_types": [
                item.get("type") for item in output if isinstance(item, dict)
            ],
            "encrypted_items": fingerprints,
            "visible_contract_ok": True,
            "plaintext_leak": False,
        },
        "trusted_self": trusted_self,
        "candidate": conditions,
    }
    return attempt, trial, None


def run_probe(args: argparse.Namespace) -> dict[str, Any]:
    trusted_key = os.getenv(args.trusted_key_env)
    candidate_key = os.getenv(args.candidate_key_env)
    if not args.juice_only and not trusted_key:
        raise SystemExit(f"缺少可信 API 临时密钥环境变量：{args.trusted_key_env}")
    if not candidate_key:
        raise SystemExit(f"缺少待测 API 临时密钥环境变量：{args.candidate_key_env}")

    candidate = ResponsesClient(
        args.candidate_base_url, candidate_key, args.timeout, args.metadata_options
    )
    if args.juice_only:
        return run_juice_only_probe(args, candidate)
    trusted = ResponsesClient(
        args.trusted_base_url, trusted_key, args.timeout, args.metadata_options
    )
    valid_trials: list[dict[str, Any]] = []
    rejected_attempts: list[dict[str, Any]] = []
    max_attempts = args.max_attempts or args.trials * 3

    def accept_outcomes(
        outcomes: list[tuple[int, dict[str, Any] | None, dict[str, Any] | None]],
    ) -> None:
        for _attempt, trial, rejection in sorted(outcomes, key=lambda item: item[0]):
            if rejection is not None:
                rejected_attempts.append(rejection)
                continue
            assert trial is not None
            trial["trial"] = len(valid_trials) + 1
            valid_trials.append(trial)
            print_candidate_attempt_result(trial)

    if args.workers == 1:
        for attempt in range(1, max_attempts + 1):
            if len(valid_trials) >= args.trials:
                break
            accept_outcomes([
                run_encrypted_attempt(
                    args, trusted, candidate, attempt, concurrent_batch=False
                )
            ])
    else:
        next_attempt = 1
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            while len(valid_trials) < args.trials and next_attempt <= max_attempts:
                remaining = args.trials - len(valid_trials)
                batch_size = min(args.workers, remaining, max_attempts - next_attempt + 1)
                batch = list(range(next_attempt, next_attempt + batch_size))
                next_attempt += batch_size
                print(
                    f"\n并发启动 COT 任务 {batch[0]}–{batch[-1]}（并发 {batch_size}）",
                    flush=True,
                )
                futures = [
                    executor.submit(
                        run_encrypted_attempt,
                        args,
                        trusted,
                        candidate,
                        attempt,
                        concurrent_batch=True,
                    )
                    for attempt in batch
                ]
                outcomes = [future.result() for future in as_completed(futures)]
                accept_outcomes(outcomes)

    def count_exact(condition: str) -> int:
        return sum(bool(trial["candidate"][condition]["exact"]) for trial in valid_trials)

    candidate_attempt_count = len(valid_trials)
    complete_trial_count = sum(
        all(result.get("status") != "error" for result in trial["candidate"].values())
        for trial in valid_trials
    )
    valid_count = candidate_attempt_count
    full_exact = count_exact("full")
    no_id_exact = count_exact("without_ids")
    message_exact = count_exact("message_only")
    corrupt_exact = count_exact("corrupted_ciphertext")
    plaintext_leaks = sum(
        bool(result.get("plaintext_leak"))
        for trial in valid_trials
        for result in trial["candidate"].values()
    )
    candidate_request_errors = sum(
        result.get("status") == "error"
        for trial in valid_trials
        for result in trial["candidate"].values()
    )
    candidate_error_rounds = sum(
        any(result.get("status") == "error" for result in trial["candidate"].values())
        for trial in valid_trials
    )
    candidate_retry_rounds = sum(
        any(result.get("transport_attempts", 1) > 1 for result in trial["candidate"].values())
        for trial in valid_trials
    )
    juice_repeats = getattr(args, "juice_repeats", 3)
    no_juice = getattr(args, "no_juice", False)
    juice_observations: list[dict[str, Any]] = []
    output_literal_controls: list[dict[str, Any]] = []
    if not no_juice:
        juice_observations = run_juice_batch(args, candidate)
        time.sleep(random_float(args.candidate_min_gap, args.candidate_max_gap))
        output_literal_controls = run_single_output_literal_controls(args, candidate)
    juice_summary = summarize_juice(juice_observations)
    output_literal_summary = summarize_output_literal_controls(
        output_literal_controls
    )
    required_matches = max(args.min_matches, math.ceil(args.min_match_rate * args.trials))

    verdict, reason = encrypted_state_verdict(
        attempts=valid_count,
        required_attempts=args.trials,
        full_exact=full_exact,
        without_ids_exact=no_id_exact,
        required_matches=required_matches,
        message_only_exact=message_exact,
        corrupted_ciphertext_exact=corrupt_exact,
        plaintext_leaks=plaintext_leaks,
    )
    network_summary = connection_quality(candidate_error_rounds, candidate_retry_rounds)
    combined = combined_summary(
        verdict, juice_summary, args.candidate_model, network_summary
    )
    combined["output_literal_control_status"] = (
        output_literal_summary["status"] if not no_juice else "not_run"
    )

    return {
        "schema_version": 6,
        "mode": "combined_single_v3_1_1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "encrypted_state_verdict": verdict,
        "combined_verdict": combined["status"],
        "reason": reason,
        "scope": (
            "Encrypted reasoning-state compatibility with the trusted GPT-5.6 source. "
            "This is not proof of physical backend identity and cannot distinguish Sol, Terra, or Luna."
        ),
        "configuration": {
            "request_metadata": args.metadata_options.report_config(),
            "detection_mode": "combined" if not no_juice else "encrypted_only",
            "trusted_base_url": args.trusted_base_url,
            "trusted_model": args.trusted_model,
            "candidate_base_url": args.candidate_base_url,
            "candidate_model": args.candidate_model,
            "requested_candidate_attempts": args.trials,
            "requested_valid_trials": args.trials,
            "max_attempts": max_attempts,
            "required_matches_per_positive_condition": required_matches,
            "min_match_rate": args.min_match_rate,
            "min_matches": args.min_matches,
            "candidate_transient_retries": args.candidate_retries,
            "candidate_request_gap_seconds": [args.candidate_min_gap, args.candidate_max_gap],
            "single_request_workers": args.workers,
            "single_concurrency_scope": "complete_cot_trials",
            "nested_candidate_variant_concurrency": False,
            "candidate_errors_remain_in_verdict_denominator": True,
            "candidate_error_round_blocks_passing": False,
            "candidate_retry_round_blocks_passing": False,
            "network_quality_reported_separately": True,
            "juice_probe_enabled": not no_juice,
            "juice_repeats_per_effort": juice_repeats,
            "juice_high_window": JUICE_HIGH_WINDOW,
            "juice_other_window": JUICE_OTHER_WINDOW,
            "output_literal_control_enabled": not no_juice,
            "output_literal_control_values": ["48", "32"],
            "output_literal_control_value_probability": 0.5,
            "output_literal_control_single_requests": (
                len(OUTPUT_LITERAL_CONTROL_VALUES) if not no_juice else 0
            ),
            "output_literal_control_window": OUTPUT_LITERAL_CONTROL_WINDOW,
            "juice_high_mixing_zero_tolerance": True,
            "juice_known_cross_effort_conflict_zero_tolerance": True,
            "juice_mixing_flag_scope": "entire_run",
            "keys_persisted": False,
            "raw_ciphertext_persisted": False,
        },
        "summary": {
            "candidate_attempts": candidate_attempt_count,
            "complete_trials": complete_trial_count,
            "valid_trials": valid_count,
            "rejected_trusted_attempts": len(rejected_attempts),
            "candidate_full_exact": full_exact,
            "candidate_without_ids_exact": no_id_exact,
            "candidate_message_only_exact": message_exact,
            "candidate_corrupted_ciphertext_exact": corrupt_exact,
            "candidate_request_plaintext_leaks": plaintext_leaks,
            "candidate_request_errors": candidate_request_errors,
            "candidate_error_rounds": candidate_error_rounds,
            "candidate_retry_rounds": candidate_retry_rounds,
            "blind_guess_upper_tail_full": f"{blind_guess_tail_probability(full_exact, valid_count):.3e}",
            "blind_guess_upper_tail_without_ids": f"{blind_guess_tail_probability(no_id_exact, valid_count):.3e}",
        },
        "network_summary": network_summary,
        "juice_summary": juice_summary,
        "output_literal_control_summary": (
            output_literal_summary if not no_juice else None
        ),
        "combined_summary": combined,
        "juice_observations": juice_observations,
        "output_literal_control_observations": output_literal_controls,
        "candidate_attempts": valid_trials,
        "valid_trials": valid_trials,
        "rejected_attempts": rejected_attempts,
        "limitations": [
            "A candidate can pass by proxying to a compatible GPT-5.6 backend.",
            "A future or different model with backward-compatible reasoning decryption can pass.",
            "The probe establishes capability compatibility, not model weights, ownership, or hosting identity.",
            "Sol, Terra, and Luna share this observable compatibility and cannot be reliably distinguished here.",
            "Juice is an auxiliary visible-output fingerprint and can be spoofed by a relay.",
        ],
    }


def self_test() -> None:
    values = {
        "reverse": ("1234567891", "1987654321"),
        "rotate_left_3": ("1234567891", "4567891123"),
        "complement_9": ("1234567891", "8765432108"),
    }
    for task, (value, expected) in values.items():
        assert transform(task, value) == expected
    sample = [
        {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": "abcdef"},
        {"type": "message", "id": "msg_1", "content": [{"type": "output_text", "text": "READY"}]},
    ]
    assert len(context_variant(sample, "message_only")) == 1
    no_ids = context_variant(sample, "without_ids")
    assert all("id" not in item for item in no_ids)
    corrupted = context_variant(sample, "corrupted_ciphertext")
    assert corrupted[0]["encrypted_content"] != sample[0]["encrypted_content"]
    assert encrypted_fingerprints(sample)[0]["sha256"] == sha256("abcdef")
    assert classify_visible_answer("8.855")["normalized_value"] == "8.855"
    assert classify_visible_answer("I can't provide that.")["kind"] == "refusal"
    assert matching_models("high", "40855") == ["gpt_5_6_sol"]
    assert matching_models("high", "32") == ["gpt_5_6_terra"]
    assert matching_models("high", "48") == ["gpt_5_6_luna"]
    assert set(matching_models("low", "8")) == {
        "gpt_5_6_sol", "gpt_5_6_luna", "gpt_5_4_mini"
    }
    noisy_verdict, _ = encrypted_state_verdict(
        attempts=20,
        required_attempts=20,
        full_exact=16,
        without_ids_exact=15,
        required_matches=15,
        message_only_exact=0,
        corrupted_ciphertext_exact=0,
        plaintext_leaks=0,
    )
    assert noisy_verdict == "gpt_5_6_encrypted_state_compatible"
    assert connection_quality(1, 2)["status"] == "unstable"
    assert connection_quality(0, 2)["status"] == "intermittent"
    assert connection_quality(0, 0)["status"] == "smooth"

    def juice_observation(effort: str, value: str) -> dict[str, Any]:
        return {
            "effort": effort,
            "status": "ok",
            "answer_kind": "number",
            "normalized_value": value,
            "matched_models": matching_models(effort, value),
        }

    sol = [
        juice_observation("high", "40855"),
        juice_observation("low", "8"),
        juice_observation("high", "40850"),
        juice_observation("medium", "16"),
        juice_observation("high", "40855"),
    ]
    sol_summary = summarize_juice(sol)
    assert sol_summary["status"] == "classified"
    assert sol_summary["likely_model"] == "gpt_5_6_sol"
    assert sol_summary["confidence"] == "high"
    mixed = sol + [juice_observation("high", "48")] + [
        juice_observation("high", "40855") for _ in range(5)
    ]
    mixed_summary = summarize_juice(mixed)
    assert mixed_summary["status"] == "mixed_or_inconsistent"
    assert set(mixed_summary["session_distinct_high_groups"]) == {
        "gpt_5_6_sol", "gpt_5_6_luna"
    }
    exact_controls = [
        {"status": "ok", "exact_output": True, "result_kind": "exact_expected"}
        for _ in range(20)
    ]
    exact_control_summary = summarize_output_literal_controls(exact_controls)
    assert exact_control_summary["status"] == "no_rewrite_observed"
    sticky_controls = [
        {
            "status": "ok",
            "exact_output": False,
            "result_kind": "altered_number",
            "observed_text": "40",
            "normalized_value": "40",
        },
        *exact_controls,
    ]
    sticky_control_summary = summarize_output_literal_controls(sticky_controls)
    assert sticky_control_summary["observations_in_window"] == 20
    assert sticky_control_summary["non_exact_successes"] == 0
    assert sticky_control_summary["session_non_exact_successes"] == 1
    assert sticky_control_summary["status"] == "output_rewrite_suspected"
    print(
        "自检：通过（模型判定、Juice 混用零容忍、高档字面量改写粘性告警）"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-base-url")
    parser.add_argument("--trusted-model", default="gpt-5.6-sol")
    parser.add_argument("--trusted-key-env", default="TRUSTED_API_KEY")
    parser.add_argument("--candidate-base-url")
    parser.add_argument("--candidate-model", default="gpt-5.6-sol")
    parser.add_argument("--candidate-key-env", default="CANDIDATE_API_KEY")
    parser.add_argument("--trials", type=int, default=12)
    parser.add_argument("--max-attempts", type=int)
    parser.add_argument("--min-match-rate", type=float, default=0.5)
    parser.add_argument("--min-matches", type=int, default=4)
    parser.add_argument("--candidate-retries", type=int, default=2)
    parser.add_argument("--candidate-min-gap", type=float, default=2.0)
    parser.add_argument("--candidate-max-gap", type=float, default=5.0)
    parser.add_argument("--juice-repeats", type=int, default=3)
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="parallel request workers for one-shot detection (1-16)",
    )
    parser.add_argument("--no-juice", action="store_true")
    parser.add_argument(
        "--juice-only",
        action="store_true",
        help="skip encrypted-state challenges and run only Juice fingerprint requests",
    )
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--output", type=Path, default=Path("gpt56_probe_report.json"))
    add_metadata_arguments(parser)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    args.metadata_options = metadata_options_from_args(args)
    if args.self_test:
        return args
    if not args.candidate_base_url:
        parser.error("--candidate-base-url is required")
    if not args.juice_only and not args.trusted_base_url:
        parser.error("--trusted-base-url is required unless --juice-only is used")
    if args.no_juice and args.juice_only:
        parser.error("--no-juice and --juice-only cannot be used together")
    if not args.juice_only and args.trials < 4:
        parser.error("--trials must be at least 4")
    if args.min_matches < 3:
        parser.error("--min-matches must be at least 3")
    if not 0 < args.min_match_rate <= 1:
        parser.error("--min-match-rate must be in (0, 1]")
    if not 0 <= args.candidate_retries <= 5:
        parser.error("--candidate-retries must be between 0 and 5")
    if args.candidate_min_gap < 0 or args.candidate_max_gap < args.candidate_min_gap:
        parser.error("candidate gaps must satisfy 0 <= min <= max")
    if not 1 <= args.juice_repeats <= 20:
        parser.error("juice-repeats must be between 1 and 20")
    if not 1 <= args.workers <= 16:
        parser.error("workers must be between 1 and 16")
    return args


def main() -> int:
    args = parse_args()
    if args.self_test:
        self_test()
        return 0
    report = run_probe(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    report.setdefault("configuration", {})["html_report_path"] = str(
        args.output.with_suffix(".html").resolve()
    )
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    write_report_html(report, args.output)
    print_probe_summary(report, args.output)
    if args.juice_only:
        return 0 if report["combined_verdict"] == "juice_only_variant_consistent" else 1
    if args.no_juice:
        return 0 if report["verdict"] == "gpt_5_6_encrypted_state_compatible" else 1
    return 0 if report["combined_verdict"] == "compatible_and_variant_consistent" else 1


if __name__ == "__main__":
    raise SystemExit(main())
