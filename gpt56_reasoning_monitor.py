#!/usr/bin/env python3
"""Continuously monitor GPT-5.6 encrypted-state compatibility."""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import secrets
import time
from typing import Any

from gpt56_report_html import write_report_html
from gpt56_request_metadata import (
    add_metadata_arguments,
    format_attempt_logs,
    format_metadata_log,
    metadata_options_from_args,
)

from gpt56_juice_probe import (
    AUXILIARY_EFFORTS,
    EFFORT_LABELS_CN,
    JUICE_HIGH_WINDOW,
    JUICE_OTHER_WINDOW,
    MODEL_LABELS_CN,
    OUTPUT_LITERAL_CONTROL_WINDOW,
    combined_summary,
    format_juice_effort_stats_cn,
    juice_connection_quality,
    juice_only_summary,
    juice_prompt_mode,
    randomized_monitor_efforts,
    randomized_output_literal_control_enabled,
    run_output_literal_control,
    run_juice_request,
    summarize_output_literal_controls,
    summarize_juice,
)
from gpt56_reasoning_probe import (
    ProbeError,
    ResponsesClient,
    connection_quality,
    context_variant,
    encrypted_state_verdict,
    encrypted_fingerprints,
    output_text,
    random_ten_digits,
    redact,
    sha256,
    transform,
)

TASK_PROMPTS = {
    "reverse": (
        "In hidden reasoning, take the ten-digit input {value} and compute B by reversing all ten digits. Retain the exact ten-digit B for the next turn. Do not expose the input, B, intermediate work, or any hint in visible output. Your entire visible response must be exactly READY",
    ),
    "rotate_left_3": (
        "In hidden reasoning, take the ten-digit input {value} and compute B by moving its first three digits to the end without changing any other order. Retain the exact ten-digit B for the next turn. Reveal no digits or work. Your complete visible response must be exactly READY",
    ),
    "complement_9": (
        "In hidden reasoning, transform the ten-digit input {value} digit by digit using d -> 9-d and call the resulting ten-character digit string B. Retain B for the next turn. Do not reveal any input, result, or work. Your entire visible response must be exactly READY",
    ),
}
RECALL_PROMPT = (
    "Return only the exact ten-digit B retained in the preceding hidden state. "
    "If that state is unavailable, return exactly UNKNOWN. Do not guess or recompute."
)

CONDITIONS = ("full", "without_ids", "message_only", "corrupted_ciphertext")
TRANSIENT_HTTP_STATUSES = {429, 500, 502, 503, 504}


def choice(values: tuple[Any, ...] | list[Any]) -> Any:
    return values[secrets.randbelow(len(values))]


def shuffled(values: tuple[str, ...]) -> list[str]:
    remaining = list(values)
    result: list[str] = []
    while remaining:
        result.append(remaining.pop(secrets.randbelow(len(remaining))))
    return result


def recall_payload(model: str, context: list[Any], prompt: str) -> dict[str, Any]:
    return {
        "model": model,
        "input": copy.deepcopy(context) + [{"role": "user", "content": prompt}],
        "reasoning": {"effort": "high"},
        "include": ["reasoning.encrypted_content"],
        "store": False,
    }


def call_and_score(
    client: ResponsesClient,
    model: str,
    context: list[Any],
    expected: str,
    *,
    max_transport_attempts: int = 1,
    retry_base_seconds: float = 2.0,
) -> dict[str, Any]:
    payload = recall_payload(model, context, RECALL_PROMPT)
    serialized = json.dumps(redact(payload), ensure_ascii=False)
    if expected in serialized:
        return {
            "status": "invalid_probe",
            "exact": False,
            "plaintext_leak": True,
            "error": "expected value appeared in request plaintext",
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
                "prompt_variant_sha256": sha256(RECALL_PROMPT),
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

def seed_payload(model: str, prompt: str) -> dict[str, Any]:
    return {
        "model": model,
        "input": [{"role": "user", "content": prompt}],
        "reasoning": {"effort": "high"},
        "include": ["reasoning.encrypted_content"],
        "store": False,
    }


def run_one_challenge(
    trusted: ResponsesClient,
    candidate: ResponsesClient,
    trusted_model: str,
    candidate_model: str,
    task: str,
    candidate_retries: int,
    candidate_min_gap: float,
    candidate_max_gap: float,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    input_value = random_ten_digits()
    expected = transform(task, input_value)
    seed_prompt = choice(TASK_PROMPTS[task]).format(value=input_value)
    try:
        seed, seed_meta = trusted.post(seed_payload(trusted_model, seed_prompt))
    except ProbeError as exc:
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "trusted_seed_error",
            "task": task,
            "http_status": exc.status,
            "error": redact(str(exc)),
            "request_metadata": exc.metadata,
        }

    output = seed.get("output")
    visible = output_text(seed)
    if not isinstance(output, list):
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "missing_output_array",
            "task": task,
        }
    fingerprints = encrypted_fingerprints(output)
    sanitized_output = json.dumps(redact(output), ensure_ascii=False)
    visible_leak = input_value in sanitized_output or expected in sanitized_output
    if visible != "READY" or not fingerprints or visible_leak:
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "invalid_trusted_seed",
            "task": task,
            "visible_contract_ok": visible == "READY",
            "encrypted_reasoning_items": len(fingerprints),
            "visible_plaintext_leak": visible_leak,
        }

    trusted_self = call_and_score(
        trusted, trusted_model, context_variant(output, "full"), expected
    )
    if not trusted_self["exact"]:
        return None, {
            "time": datetime.now(timezone.utc).isoformat(),
            "reason": "trusted_state_not_self_verifiable",
            "task": task,
            "seed_prompt_variant_sha256": sha256(
                seed_prompt.replace(input_value, "{challenge}")
            ),
            "trusted_self": trusted_self,
        }

    condition_order = shuffled(CONDITIONS)
    conditions: dict[str, Any] = {}
    for index, variant in enumerate(condition_order):
        conditions[variant] = call_and_score(
            candidate,
            candidate_model,
            context_variant(output, variant),
            expected,
            max_transport_attempts=candidate_retries + 1,
        )
        if index + 1 < len(condition_order):
            time.sleep(random_float(candidate_min_gap, candidate_max_gap))

    record = {
        "time": datetime.now(timezone.utc).isoformat(),
        "task": task,
        "seed_prompt_variant_sha256": sha256(seed_prompt.replace(input_value, "{challenge}")),
        "condition_order": condition_order,
        "expected_sha256": sha256(expected),
        "trusted_seed": {
            **seed_meta,
            "encrypted_items": fingerprints,
            "plaintext_leak": False,
        },
        "trusted_self": trusted_self,
        "candidate": conditions,
    }
    errors = {
        variant: result
        for variant, result in conditions.items()
        if result.get("status") == "error"
    }
    if errors:
        return None, {
            "time": record["time"],
            "reason": "candidate_request_error",
            "task": task,
            "conditions": errors,
            "candidate_attempt": record,
        }
    return record, None

def window_summary(
    attempts: list[dict[str, Any]], window_size: int, required: int
) -> dict[str, Any]:
    window = attempts[-window_size:]
    attempt_count = len(window)
    error_rounds = sum(
        any(result.get("status") == "error" for result in item["candidate"].values())
        for item in window
    )
    retry_rounds = sum(
        any(result.get("transport_attempts", 1) > 1 for result in item["candidate"].values())
        for item in window
    )
    complete_count = attempt_count - error_rounds
    exact = {
        name: sum(bool(item["candidate"][name].get("exact")) for item in window)
        for name in CONDITIONS
    }
    leaks = sum(
        bool(result.get("plaintext_leak"))
        for item in window
        for result in item["candidate"].values()
    )
    task_counts = {
        task: sum(item.get("task") == task for item in window) for task in TASK_PROMPTS
    }
    verdict, _ = encrypted_state_verdict(
        attempts=attempt_count,
        required_attempts=window_size,
        full_exact=exact["full"],
        without_ids_exact=exact["without_ids"],
        required_matches=required,
        message_only_exact=exact["message_only"],
        corrupted_ciphertext_exact=exact["corrupted_ciphertext"],
        plaintext_leaks=leaks,
        warming_verdict="warming_up",
        incompatible_verdict="not_compatible_in_this_window",
    )
    network = connection_quality(error_rounds, retry_rounds)
    return {
        "verdict": verdict,
        "network_summary": network,
        "candidate_attempts_in_window": attempt_count,
        "complete_trials_in_window": complete_count,
        "valid_trials_in_window": complete_count,
        "candidate_error_rounds": error_rounds,
        "candidate_retry_rounds": retry_rounds,
        "window_size": window_size,
        "required_positive_matches": required,
        "full_exact": exact["full"],
        "without_ids_exact": exact["without_ids"],
        "message_only_exact": exact["message_only"],
        "corrupted_ciphertext_exact": exact["corrupted_ciphertext"],
        "plaintext_leaks": leaks,
        "task_counts": task_counts,
    }

def monitor_health_summary(
    attempts: list[dict[str, Any]],
    consecutive_trusted_failures: int,
    now: datetime,
    stale_after_seconds: int,
) -> dict[str, Any]:
    last_candidate_at = attempts[-1]["time"] if attempts else None
    evidence_age_seconds: int | None = None
    if last_candidate_at:
        evidence_age_seconds = max(
            0,
            int((now - datetime.fromisoformat(last_candidate_at)).total_seconds()),
        )

    unavailable = consecutive_trusted_failures >= 3 or (
        evidence_age_seconds is not None
        and evidence_age_seconds > stale_after_seconds
    )
    if unavailable:
        status = "trusted_source_unavailable"
        title = "可信端不可用，监控未刷新"
        detail = (
            f"可信端已连续失败 {consecutive_trusted_failures} 轮；"
            + (
                f"距上次待测挑战 {evidence_age_seconds} 秒"
                if evidence_age_seconds is not None
                else "尚未产生待测挑战"
            )
        )
    elif consecutive_trusted_failures:
        status = "trusted_source_degraded"
        title = "可信端有波动"
        detail = f"可信端连续失败 {consecutive_trusted_failures} 轮，等待自动恢复"
    elif not attempts:
        status = "collecting"
        title = "正在等待首个有效挑战"
        detail = "监控刚启动，尚未形成待测端样本"
    else:
        status = "healthy"
        title = "监控正常"
        detail = "可信端能够生成挑战，待测端证据正在刷新"

    backoff_seconds = 0
    if status == "trusted_source_unavailable":
        failure_step = max(0, consecutive_trusted_failures - 3)
        backoff_seconds = min(
            240, 60 * (2 ** min(failure_step, 2))
        )

    return {
        "status": status,
        "title_cn": title,
        "detail_cn": detail,
        "current_monitoring_effective": status in {
            "healthy", "trusted_source_degraded"
        },
        "consecutive_trusted_failures": consecutive_trusted_failures,
        "last_candidate_at": last_candidate_at,
        "candidate_evidence_age_seconds": evidence_age_seconds,
        "stale_after_seconds": stale_after_seconds,
        "next_retry_backoff_seconds": backoff_seconds,
    }


def juice_only_monitor_health_summary(
    observations: list[dict[str, Any]],
    now: datetime,
    stale_after_seconds: int,
) -> dict[str, Any]:
    last_juice_at = observations[-1]["time"] if observations else None
    evidence_age_seconds: int | None = None
    if last_juice_at:
        evidence_age_seconds = max(
            0,
            int((now - datetime.fromisoformat(last_juice_at)).total_seconds()),
        )
    consecutive_candidate_failures = 0
    for item in reversed(observations):
        if item.get("status") != "error":
            break
        consecutive_candidate_failures += 1

    unavailable = consecutive_candidate_failures >= 3 or (
        evidence_age_seconds is not None
        and evidence_age_seconds > stale_after_seconds
    )
    if unavailable:
        status = "candidate_source_unavailable"
        title = "待测端不可用，Juice 监控未刷新"
        detail = (
            f"待测端连续失败 {consecutive_candidate_failures} 次；"
            + (
                f"距上次 Juice 请求 {evidence_age_seconds} 秒"
                if evidence_age_seconds is not None
                else "尚未产生 Juice 样本"
            )
        )
    elif consecutive_candidate_failures:
        status = "candidate_source_degraded"
        title = "待测端有波动"
        detail = f"待测端连续失败 {consecutive_candidate_failures} 次，等待自动恢复"
    elif not observations:
        status = "collecting"
        title = "正在等待首个 Juice 样本"
        detail = "Juice-only 监控刚启动"
    else:
        status = "healthy"
        title = "Juice 监控正常"
        detail = "待测端 Juice 证据正在刷新"

    backoff_seconds = 0
    if status == "candidate_source_unavailable":
        failure_step = max(0, consecutive_candidate_failures - 3)
        backoff_seconds = min(240, 60 * (2 ** min(failure_step, 2)))
    return {
        "status": status,
        "title_cn": title,
        "detail_cn": detail,
        "current_monitoring_effective": status in {
            "healthy", "candidate_source_degraded"
        },
        "consecutive_trusted_failures": 0,
        "last_candidate_at": None,
        "candidate_evidence_age_seconds": None,
        "consecutive_candidate_failures": consecutive_candidate_failures,
        "last_juice_at": last_juice_at,
        "juice_evidence_age_seconds": evidence_age_seconds,
        "stale_after_seconds": stale_after_seconds,
        "next_retry_backoff_seconds": backoff_seconds,
        "trusted_source_applicable": False,
    }


def apply_monitor_health(
    combined: dict[str, Any], health: dict[str, Any]
) -> dict[str, Any]:
    result = copy.deepcopy(combined)
    result["historical_result"] = {
        "status": combined["status"],
        "title_cn": combined["title_cn"],
        "passed_cn": combined["passed_cn"],
        "explanation_cn": combined["explanation_cn"],
    }
    result["monitor_health_status"] = health["status"]
    if health["status"] == "trusted_source_unavailable":
        if combined["status"] == "compatible_and_variant_consistent":
            result["status"] = "historical_pass_trusted_source_unavailable"
            result["title_cn"] = "历史检测通过，但当前监控未刷新"
            result["passed_cn"] = "历史通过，当前未确认"
        else:
            result["status"] = "historical_result_trusted_source_unavailable"
            result["title_cn"] = (
                f"当前监控未刷新；历史结论：{combined['title_cn']}"
            )
            result["passed_cn"] = "历史结果，当前未确认"
        result["explanation_cn"] = (
            f"{combined['explanation_cn']} 当前可信端不可用，"
            "没有新挑战到达待测端，因此这只是历史窗口结论。"
        )
    elif health["status"] == "trusted_source_degraded":
        result["explanation_cn"] = (
            f"{combined['explanation_cn']} 可信端暂有波动，程序正在自动重试。"
        )
    return result


def apply_juice_monitor_health(
    combined: dict[str, Any], health: dict[str, Any]
) -> dict[str, Any]:
    result = copy.deepcopy(combined)
    result["historical_result"] = {
        "status": combined["status"],
        "title_cn": combined["title_cn"],
        "passed_cn": combined["passed_cn"],
        "explanation_cn": combined["explanation_cn"],
    }
    result["monitor_health_status"] = health["status"]
    if health["status"] == "candidate_source_unavailable":
        result["status"] = "historical_juice_result_candidate_unavailable"
        result["title_cn"] = f"Juice 监控未刷新；历史结论：{combined['title_cn']}"
        result["passed_cn"] = "历史结果，当前未确认"
        result["explanation_cn"] = (
            f"{combined['explanation_cn']} 当前待测端不可用，没有新的 Juice 证据。"
        )
    elif health["status"] == "candidate_source_degraded":
        result["explanation_cn"] = (
            f"{combined['explanation_cn']} 待测端暂有波动，程序正在自动重试。"
        )
    return result


def empty_strong_window_summary(window_size: int, required: int) -> dict[str, Any]:
    return {
        "verdict": "not_run_juice_only",
        "network_summary": {
            "status": "not_applicable",
            "title_cn": "不适用",
            "detail_cn": "Juice-only 模式未运行加密状态挑战",
        },
        "candidate_attempts_in_window": 0,
        "complete_trials_in_window": 0,
        "valid_trials_in_window": 0,
        "candidate_error_rounds": 0,
        "candidate_retry_rounds": 0,
        "window_size": window_size,
        "required_positive_matches": required,
        "full_exact": 0,
        "without_ids_exact": 0,
        "message_only_exact": 0,
        "corrupted_ciphertext_exact": 0,
        "plaintext_leaks": 0,
        "task_counts": {},
    }

def atomic_write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)
    write_report_html(report, path)


def random_interval(minimum: int, maximum: int) -> int:
    return minimum + secrets.randbelow(maximum - minimum + 1)

def random_float(minimum: float, maximum: float) -> float:
    if maximum <= minimum:
        return minimum
    return minimum + (maximum - minimum) * (secrets.randbelow(1_000_001) / 1_000_000)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-base-url")
    parser.add_argument("--trusted-model", default="gpt-5.6-sol")
    parser.add_argument("--candidate-base-url", required=True)
    parser.add_argument("--candidate-model", default="gpt-5.6-sol")
    parser.add_argument("--trusted-key-env", default="TRUSTED_API_KEY")
    parser.add_argument("--candidate-key-env", default="CANDIDATE_API_KEY")
    parser.add_argument("--min-interval", type=int, default=150)
    parser.add_argument("--max-interval", type=int, default=210)
    parser.add_argument("--window", type=int, default=20)
    parser.add_argument("--required-matches", type=int, default=15)
    parser.add_argument("--candidate-retries", type=int, default=2)
    parser.add_argument("--candidate-min-gap", type=float, default=2.0)
    parser.add_argument("--candidate-max-gap", type=float, default=5.0)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument("--max-valid-trials", type=int, default=0)
    parser.add_argument("--max-cycles", type=int, default=0)
    parser.add_argument(
        "--juice-only",
        action="store_true",
        help="skip trusted encrypted-state challenges and continuously probe Juice only",
    )
    parser.add_argument("--output", type=Path, default=Path("gpt56-monitor-report.json"))
    add_metadata_arguments(parser)
    args = parser.parse_args()
    args.metadata_options = metadata_options_from_args(args)
    if args.min_interval < 1 or args.max_interval < args.min_interval:
        parser.error("intervals must satisfy 1 <= min <= max")
    if not args.juice_only and not args.trusted_base_url:
        parser.error("--trusted-base-url is required unless --juice-only is used")
    if args.window < 4 or not 1 <= args.required_matches <= args.window:
        parser.error("window and required-matches are invalid")
    if not 0 <= args.candidate_retries <= 5:
        parser.error("candidate-retries must be between 0 and 5")
    if args.candidate_min_gap < 0 or args.candidate_max_gap < args.candidate_min_gap:
        parser.error("candidate gaps must satisfy 0 <= min <= max")
    if args.max_cycles < 0:
        parser.error("max-cycles must be non-negative")
    return args


TASK_LABELS = {
    "reverse": "十位数字倒序",
    "rotate_left_3": "前三位移到末尾",
    "complement_9": "逐位计算九补数",
}

FAILURE_LABELS = {
    "trusted_seed_error": "可信 API 生成状态失败",
    "missing_output_array": "可信 API 返回格式不完整",
    "invalid_trusted_seed": "可信状态不符合 READY/密文/无泄漏要求",
    "trusted_state_not_self_verifiable": "可信 API 无法自证刚生成的状态",
    "candidate_request_error": "待测 API 请求在重试后仍失败",
}

VERDICT_LABELS = {
    "warming_up": ("还在检测", "尚未判定", "还没有收集满 20 次。"),
    "gpt_5_6_encrypted_state_compatible": (
        "强检测通过",
        "是",
        "极高置信度具备 GPT-5.6 加密状态处理能力。",
    ),
    "inconclusive_candidate_unstable": (
        "旧版线路判定",
        "尚未判定",
        "这是旧版报告状态；新版已把模型真假和线路质量分开。",
    ),
    "inconclusive": ("证据不够", "尚不能确认", "答对次数没有达到门槛。"),
    "not_compatible_in_this_window": ("没有测到 GPT-5.6 能力", "否", "两种有效测试都没有答对。"),
    "suspicious": ("检测异常", "否", "本来不该答对的测试出现命中。"),
    "invalid": ("检测无效", "否", "请求中泄漏了正确答案。"),
}


def transport_event_count(attempt: dict[str, Any] | None) -> int:
    if not attempt:
        return 0
    return sum(
        len(result.get("transport_errors", []))
        for result in attempt["candidate"].values()
    )


def print_monitor_status(
    report: dict[str, Any],
    trial: dict[str, Any] | None,
    failure: dict[str, Any] | None,
    candidate_attempt: dict[str, Any] | None,
    juice_observation: dict[str, Any] | None,
) -> None:
    summary = report["rolling_summary"]
    combined = report["combined_summary"]
    juice = report["juice_summary"]
    network = report["network_summary"]
    health = report["monitor_health_summary"]
    juice_only = report["configuration"].get("detection_mode") == "juice_only"
    attempts = summary["candidate_attempts_in_window"]
    remaining = max(summary["window_size"] - attempts, 0)
    required = summary["required_positive_matches"]
    abnormal = summary["message_only_exact"] + summary["corrupted_ciphertext_exact"]
    confidence_cn = {
        "high": "高", "medium": "中", "preliminary": "初步", "insufficient": "不足"
    }.get(juice["confidence"], juice["confidence"])

    print("\n" + "=" * 62)
    print(f"[第 {report['cycles']} 轮] {datetime.now().astimezone():%Y-%m-%d %H:%M:%S}")
    print(f"当前结论：{combined['title_cn']}")
    print(f"监控状态：{health['title_cn']}（{health['detail_cn']}）")
    if juice_only:
        print("模型能力：未检测（当前为 Juice-only 持续监控）")
    elif summary["verdict"] == "warming_up":
        print(f"进度：{attempts}/{summary['window_size']}，还差 {remaining} 轮")
    elif summary["verdict"] == "gpt_5_6_encrypted_state_compatible":
        label = (
            "历史模型能力"
            if health["status"] == "trusted_source_unavailable"
            else "模型能力"
        )
        print(f"{label}：强检测通过，极高置信度具备 GPT-5.6 能力")
    else:
        print(f"模型能力：{VERDICT_LABELS.get(summary['verdict'], (summary['verdict'],))[0]}")

    if not juice_only:
        print(
            f"答对情况：完整状态 {summary['full_exact']}/{required}，"
            f"去掉编号 {summary['without_ids_exact']}/{required}；"
            f"异常 {abnormal}，泄漏 {summary['plaintext_leaks']}"
        )
    mixed = juice["status"] == "mixed_or_inconsistent"
    high_stats = juice["effort_stats"]["high"]
    print(
        f"具体型号：{juice['likely_model_cn']}（置信度{confidence_cn}，"
        f"高档窗口 {high_stats['observations']}/{high_stats['window_limit']}，"
        f"有效数字 {high_stats['numeric_samples']}）；"
        f"混用：{'已发现' if mixed else '未发现'}"
    )
    print("分档统计：" + format_juice_effort_stats_cn(juice))
    output_control = report["output_literal_control_summary"]
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
    print(f"线路情况：{network['title_cn']}（{network['detail_cn']}）")
    if juice_observation is not None:
        suffix = format_metadata_log(juice_observation)
        if suffix:
            print(f"Juice request{suffix}")
    controls = report.get("output_literal_control_observations", [])
    if controls:
        suffix = format_metadata_log(controls[-1])
        if suffix:
            print(f"Output control request{suffix}")

    current = None if juice_only else trial or candidate_attempt
    if current is not None:
        candidate = current["candidate"]
        abnormal_now = int(bool(candidate["message_only"].get("exact"))) + int(
            bool(candidate["corrupted_ciphertext"].get("exact"))
        )
        retry_events = transport_event_count(current)
        failed = sum(item.get("status") == "error" for item in candidate.values())
        print(
            f"本轮：{TASK_LABELS.get(current['task'], current['task'])}；"
            f"完整状态{'答对' if candidate['full'].get('exact') else '未答对'}，"
            f"去掉编号{'答对' if candidate['without_ids'].get('exact') else '未答对'}，"
            f"异常 {abnormal_now}，失败 {failed}，重试 {retry_events}"
        )
        for variant, result in candidate.items():
            for line in format_attempt_logs(variant, result):
                print(f"  {line}")
        trusted_seed = current.get("trusted_seed", {})
        if trusted_seed:
            print(f"  trusted seed{format_metadata_log(trusted_seed)}")
        for line in format_attempt_logs("trusted self", current.get("trusted_self", {})):
            print(f"  {line}")
    elif failure is not None and not juice_only:
        reason = failure.get("reason", "unknown")
        print(f"本轮未测试待测端：{FAILURE_LABELS.get(reason, reason)}")

    if mixed:
        print("严重警报：已经发现互相冲突的型号结果，本会话会一直保留这个标记。")
    if output_control["status"] == "output_rewrite_suspected":
        latest = output_control["session_anomalies"][-1]
        print(
            "严重警报：高档字面量对照返回非预期内容："
            f"要求 {latest.get('expected_text')!r}，"
            f"得到 {latest.get('observed_text')!r}。本会话持续保留。"
        )
    print(f"详细报告：{report['configuration']['report_path']}")
    print("=" * 62, flush=True)

def main() -> int:
    args = parse_args()
    trusted_key = os.getenv(args.trusted_key_env)
    candidate_key = os.getenv(args.candidate_key_env)
    if not candidate_key:
        raise SystemExit("缺少待测 API 的临时密钥环境变量")
    if not args.juice_only and not trusted_key:
        raise SystemExit("缺少可信 API 的临时密钥环境变量")
    candidate = ResponsesClient(
        args.candidate_base_url, candidate_key, args.timeout, args.metadata_options
    )
    trusted = (
        None
        if args.juice_only
        else ResponsesClient(
            args.trusted_base_url, trusted_key, args.timeout, args.metadata_options
        )
    )
    trials: list[dict[str, Any]] = []
    candidate_attempts: list[dict[str, Any]] = []
    juice_observations: list[dict[str, Any]] = []
    output_literal_controls: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    started = datetime.now(timezone.utc).isoformat()
    cycle = 0
    consecutive_trusted_failures = 0
    stale_after_seconds = max(
        300, int(args.max_interval * 2 + args.timeout)
    )
    tasks = tuple(TASK_PROMPTS)
    print("=" * 66)
    if args.juice_only:
        print("GPT-5.6 Juice-only 持续监控 v3.1.1 已启动")
        print("本模式只请求待测端，不运行可信端或加密状态挑战。")
    else:
        print("GPT-5.6 API 综合检测 v3.1.1 已启动")
        print("第一层检查加密状态能力，第二层用 juice 指纹区分具体型号和发现混用。")
    print("每轮固定检测高档，并随机追加零个或一个其他档位。")
    print("按 Ctrl+C 可以随时停止，最新报告会自动保存。")
    print("模型真假和线路质量分开判断；网络重试不会把真模型直接判成假。")
    print("=" * 66, flush=True)
    try:
        while True:
            if args.max_cycles and cycle >= args.max_cycles:
                break
            if (
                not args.juice_only
                and args.max_valid_trials
                and len(trials) >= args.max_valid_trials
            ):
                break
            cycle += 1
            trial = None
            failure = None
            candidate_attempt = None
            current_attempt = None
            if args.juice_only:
                print(f"\n正在执行第 {cycle} 轮 Juice-only 检测……", flush=True)
            else:
                assert trusted is not None
                task = tasks[len(candidate_attempts) % len(tasks)]
                print(
                    f"\n正在执行第 {cycle} 轮：{TASK_LABELS.get(task, task)}……",
                    flush=True,
                )
                trial, failure = run_one_challenge(
                    trusted,
                    candidate,
                    args.trusted_model,
                    args.candidate_model,
                    task,
                    args.candidate_retries,
                    args.candidate_min_gap,
                    args.candidate_max_gap,
                )
                if trial is not None:
                    trials.append(trial)
                    candidate_attempts.append(trial)
                elif failure is not None:
                    candidate_attempt = failure.pop("candidate_attempt", None)
                    if candidate_attempt is not None:
                        candidate_attempts.append(candidate_attempt)
                    rejected.append(failure)
                current_attempt = trial or candidate_attempt
                if current_attempt is None:
                    consecutive_trusted_failures += 1
                else:
                    consecutive_trusted_failures = 0

            cycle_efforts = randomized_monitor_efforts()
            cycle_juice_observations: list[dict[str, Any]] = []
            for effort_index, juice_effort in enumerate(cycle_efforts):
                if effort_index or not args.juice_only:
                    time.sleep(
                        random_float(
                            args.candidate_min_gap, args.candidate_max_gap
                        )
                    )
                print(
                    f"正在进行 Juice 指纹：{EFFORT_LABELS_CN[juice_effort]}档……",
                    flush=True,
                )
                observation = run_juice_request(
                    candidate,
                    args.candidate_model,
                    juice_effort,
                    max_transport_attempts=args.candidate_retries + 1,
                )
                cycle_juice_observations.append(observation)
                juice_observations.append(observation)

            output_literal_control_enabled = (
                randomized_output_literal_control_enabled()
            )
            cycle_output_literal_control = None
            if output_literal_control_enabled:
                time.sleep(
                    random_float(args.candidate_min_gap, args.candidate_max_gap)
                )
                print("正在进行高档字面量输出完整性对照……", flush=True)
                cycle_output_literal_control = run_output_literal_control(
                    candidate,
                    args.candidate_model,
                    max_transport_attempts=args.candidate_retries + 1,
                )
                output_literal_controls.append(cycle_output_literal_control)
                if cycle_output_literal_control["status"] == "error":
                    control_detail = "接口错误"
                elif cycle_output_literal_control["exact_output"]:
                    control_detail = (
                        f"精确返回 {cycle_output_literal_control['expected_text']}"
                    )
                else:
                    control_detail = (
                        f"要求 {cycle_output_literal_control['expected_text']}，"
                        f"返回 {cycle_output_literal_control.get('observed_text')!r}"
                    )
                print(f"  结果：{control_detail}", flush=True)

            summary = (
                empty_strong_window_summary(args.window, args.required_matches)
                if args.juice_only
                else window_summary(
                    candidate_attempts, args.window, args.required_matches
                )
            )
            juice_summary = summarize_juice(juice_observations)
            output_literal_summary = summarize_output_literal_controls(
                output_literal_controls
            )
            report_time = datetime.now(timezone.utc)
            if args.juice_only:
                network_summary = juice_connection_quality(juice_observations)
                monitor_health = juice_only_monitor_health_summary(
                    juice_observations, report_time, stale_after_seconds
                )
                base_combined = juice_only_summary(
                    juice_summary, args.candidate_model, network_summary
                )
                combined = apply_juice_monitor_health(
                    base_combined, monitor_health
                )
            else:
                network_summary = summary["network_summary"]
                monitor_health = monitor_health_summary(
                    candidate_attempts,
                    consecutive_trusted_failures,
                    report_time,
                    stale_after_seconds,
                )
                base_combined = combined_summary(
                    summary["verdict"],
                    juice_summary,
                    args.candidate_model,
                    network_summary,
                )
                combined = apply_monitor_health(base_combined, monitor_health)
            combined["output_literal_control_status"] = (
                output_literal_summary["status"]
            )
            report = {
                "schema_version": 6,
                "mode": (
                    "continuous_juice_only_v3_1_1_monitor"
                    if args.juice_only
                    else "continuous_combined_v3_1_1_monitor"
                ),
                "started_at": started,
                "updated_at": report_time.isoformat(),
                "trusted_source_health_reported_separately": True,
                "configuration": {
                    "request_metadata": args.metadata_options.report_config(),
                    "detection_mode": (
                        "juice_only" if args.juice_only else "combined"
                    ),
                    "trusted_base_url": args.trusted_base_url,
                    "trusted_model": args.trusted_model,
                    "candidate_base_url": args.candidate_base_url,
                    "candidate_model": args.candidate_model,
                    "random_interval_seconds": [args.min_interval, args.max_interval],
                    "candidate_request_gap_seconds": [
                        args.candidate_min_gap,
                        args.candidate_max_gap,
                    ],
                    "candidate_transient_retries": args.candidate_retries,
                    "rolling_window": args.window,
                    "required_positive_matches": args.required_matches,
                    "candidate_errors_remain_in_window_denominator": True,
                    "candidate_error_round_blocks_passing": False,
                    "candidate_retry_round_blocks_passing": False,
                    "network_quality_reported_separately": True,
                    "trusted_source_health_reported_separately": True,
                    "trusted_source_applicable": not args.juice_only,
                    "candidate_evidence_stale_after_seconds": stale_after_seconds,
                    "trusted_failure_backoff_max_seconds": 240,
                    "juice_probe_enabled": True,
                    "juice_only": args.juice_only,
                    "juice_prompt_variant_mode": juice_prompt_mode(),
                    "juice_cycle_policy": "always_high_optional_one_random_auxiliary",
                    "juice_auxiliary_options": [None, *AUXILIARY_EFFORTS],
                    "juice_auxiliary_probability": 0.8,
                    "juice_high_window": JUICE_HIGH_WINDOW,
                    "juice_other_window": JUICE_OTHER_WINDOW,
                    "output_literal_control_enabled": True,
                    "output_literal_control_cycle_probability": 0.5,
                    "output_literal_control_values": ["48", "32"],
                    "output_literal_control_value_probability": 0.5,
                    "output_literal_control_window": OUTPUT_LITERAL_CONTROL_WINDOW,
                    "juice_high_mixing_zero_tolerance": True,
                    "juice_known_cross_effort_conflict_zero_tolerance": True,
                    "juice_mixing_flag_scope": "entire_session",
                    "report_path": str(args.output.resolve()),
                    "html_report_path": str(args.output.with_suffix(".html").resolve()),
                    "keys_persisted": False,
                    "raw_ciphertext_persisted": False,
                },
                "experiment_controls": [
                    "canonical prompts selected for trusted-state stability",
                    "same canonical recall prompt for every condition",
                    "balanced task rotation across candidate attempts",
                    "fresh random challenge on every cycle",
                    "randomized candidate condition order",
                    "random gap between candidate condition requests",
                    "identity-preserving Juice prompts always request the original Juice value",
                    "every cycle probes high effort and uniformly chooses zero or one auxiliary effort",
                    "every cycle independently adds a high-effort literal output control with 50 percent probability",
                    "enabled literal controls choose Luna 48 or Terra 32 with equal probability",
                    "bounded randomized backoff for transient candidate transport errors",
                    "candidate error and retry rounds stay in the denominator but only affect network quality",
                ],
                "warning": (
                    "Randomization reduces simple fixed-pattern detection only. A relay can still recognize "
                    "Responses reasoning replay or proxy all probe-like traffic to GPT-5.6."
                ),
                "cycles": cycle,
                "total_candidate_attempts": len(candidate_attempts),
                "total_juice_probes": len(juice_observations),
                "total_output_literal_controls": len(output_literal_controls),
                "last_cycle_juice_efforts": list(cycle_efforts),
                "last_cycle_output_literal_control_enabled": (
                    output_literal_control_enabled
                ),
                "last_cycle_output_literal_control_expected_text": (
                    cycle_output_literal_control.get("expected_text")
                    if cycle_output_literal_control
                    else None
                ),
                "total_valid_trials": len(trials),
                "total_rejected_attempts": len(rejected),
                "rolling_summary": summary,
                "network_summary": network_summary,
                "monitor_health_summary": monitor_health,
                "juice_summary": juice_summary,
                "output_literal_control_summary": output_literal_summary,
                "combined_summary": combined,
                "juice_observations": juice_observations,
                "output_literal_control_observations": output_literal_controls,
                "candidate_attempts": candidate_attempts,
                "valid_trials": trials,
                "rejected_attempts": rejected,
            }
            atomic_write(args.output, report)
            print_monitor_status(
                report,
                trial,
                failure,
                candidate_attempt,
                cycle_juice_observations[-1]
                if cycle_juice_observations
                else None,
            )
            if args.max_valid_trials and len(trials) >= args.max_valid_trials:
                break
            if args.max_cycles and cycle >= args.max_cycles:
                break
            delay = random_interval(args.min_interval, args.max_interval)
            delay = max(
                delay, monitor_health["next_retry_backoff_seconds"]
            )
            if monitor_health["status"] in {
                "trusted_source_unavailable", "candidate_source_unavailable"
            }:
                source = "待测端" if args.juice_only else "可信端"
                print(f"{source}异常，{delay} 秒后再试。", flush=True)
            else:
                print(f"下一轮将在 {delay} 秒后开始。", flush=True)
            time.sleep(delay)
    except KeyboardInterrupt:
        print("\n监控已由用户停止，最新脱敏报告已经保存。", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
