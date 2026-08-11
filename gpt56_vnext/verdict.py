from __future__ import annotations

from typing import Any

from .juice import TARGET_MODELS


OUTCOME_CODES = (
    "juice_pass_fingerprint_strong",
    "juice_pass_fingerprint_unclear",
    "juice_mismatch_fingerprint_strong",
    "juice_mismatch_fingerprint_unclear",
    "juice_insufficient_fingerprint_strong",
    "juice_insufficient_fingerprint_unclear",
    "possible_non_gpt",
)

MODEL_LABELS = {
    "gpt-5.6-sol": "Sol",
    "gpt-5.6-terra": "Terra",
    "gpt-5.6-luna": "Luna",
    "gpt-5.5": "GPT-5.5",
    "gpt-5.4": "GPT-5.4",
    "gpt-5.4-mini": "GPT-5.4 mini",
}

FINGERPRINT_REASON_CN = {
    "no_exact_runtime_contract": "当前题面、请求次数或请求格式没有对应的正式内置指纹基线。",
    "runtime_reference_only": "当前配置只允许显示参考匹配度，不产生正式强指向结论。",
    "runtime_contract_mismatch": "探针题面、思考强度、归一化方式或请求格式与冻结契约不一致。",
    "baseline_cells_missing": "可信基线缺少当前配置所需的探针格。",
    "candidate_samples_incomplete": "至少一个探针格未完成计划请求数的90%。",
    "no_weighted_fingerprint_family": "当前没有取得可用于比较的有效指纹家族。",
    "no_model_reached_strong_match_threshold": "三个模型都没有越过当前档位的强指向线。",
    "multiple_models_reached_threshold": "多个模型同时越过强指向线，结果存在数值异常。",
    "custom_probe_reference_only": "导入的自定义探针未经发行版正式验证，匹配度仅供参考。",
    "builtin_fingerprint_not_enabled": "当前档位没有启用内置指纹探针。",
}


def _fingerprint_rows(fingerprint: dict[str, Any]) -> list[dict[str, Any]]:
    values = fingerprint.get("fingerprint_match") or {}
    thresholds = fingerprint.get("fingerprint_thresholds") or {}
    return sorted(
        [
            {
                "model": model,
                "label_cn": MODEL_LABELS.get(model, model),
                "match": float(values.get(model, 0.0)),
                "threshold": thresholds.get(model),
                "score": (fingerprint.get("scores") or {}).get(model),
            }
            for model in TARGET_MODELS
        ],
        key=lambda row: row["match"],
        reverse=True,
    )


def _juice_state(
    juice: dict[str, Any],
    output: dict[str, Any],
    coverage: dict[str, Any],
) -> str:
    deterministic_anomaly = bool(
        juice.get("juice_mixed")
        or output.get("hard_anomaly")
        or output.get("sticky_hard_anomaly")
        or coverage.get("hard_anomaly")
        or coverage.get("sticky_hard_anomaly")
    )
    if deterministic_anomaly:
        return "mismatch"
    if juice.get("juice_all_unsuccessful"):
        return "possible_non_gpt"
    if juice.get("juice_pass"):
        return "pass"
    return "insufficient"


def _title(juice_state: str, fingerprint: dict[str, Any]) -> tuple[str, str]:
    if juice_state == "possible_non_gpt":
        return "possible_non_gpt", "可能非GPT"
    strong = fingerprint.get("fingerprint_status") == "strong_match" and bool(fingerprint.get("fingerprint_model"))
    fingerprint_part = (
        f"指纹强烈指向 {MODEL_LABELS.get(str(fingerprint['fingerprint_model']), fingerprint['fingerprint_model'])}"
        if strong else "指纹证据不明确"
    )
    juice_label = {
        "pass": "Juice通过",
        "mismatch": "Juice与申报型号不一致",
        "insufficient": "Juice证据不足",
    }[juice_state]
    code = f"juice_{'mismatch' if juice_state == 'mismatch' else juice_state}_fingerprint_{'strong' if strong else 'unclear'}"
    return code, f"{juice_label}；{fingerprint_part}"


def _subtitle(juice_state: str, fingerprint: dict[str, Any], custom: bool) -> str:
    fingerprint_model = MODEL_LABELS.get(str(fingerprint.get("fingerprint_model")), str(fingerprint.get("fingerprint_model")))
    fingerprint_reasons = set(fingerprint.get("fingerprint_unclear_reasons") or [])
    if juice_state == "possible_non_gpt":
        text = "所有达到数量要求的有效 Juice 响应均未命中已知型号指纹；也可能由统一输出改写、参数未透传或探针拦截造成。"
    elif juice_state == "pass" and fingerprint.get("fingerprint_status") == "strong_match":
        text = f"Juice 未发现型号冲突；本批行为分布与 {fingerprint_model} 的可信指纹最接近。"
    elif juice_state == "pass" and "builtin_fingerprint_not_enabled" in fingerprint_reasons:
        text = "Juice 未发现型号冲突。当前为低档，仅检测 Juice 与确定性异常，未启用行为指纹探针。"
    elif juice_state == "pass":
        text = "Juice 未发现型号冲突，但行为指纹没有形成正式强指向；请结合样本完整性和线路质量阅读。"
    elif juice_state == "mismatch" and fingerprint.get("fingerprint_status") == "strong_match":
        text = f"至少一项确定性检查与申报不一致；行为分布同时强烈指向 {fingerprint_model}。"
    elif juice_state == "mismatch":
        text = "至少一项确定性检查与申报不一致；行为指纹暂时没有形成明确方向。"
    elif fingerprint.get("fingerprint_status") == "strong_match":
        text = f"Juice 缺少至少一个思考档的申报型号命中；行为分布强烈指向 {fingerprint_model}，只能作为补充证据。"
    elif "builtin_fingerprint_not_enabled" in fingerprint_reasons:
        text = "当前为低档，仅检测 Juice 与确定性异常，未启用行为指纹探针；Juice 证据也不足，请查看未完成项目。"
    else:
        text = "Juice 和行为指纹都没有取得足够证据，请先检查未完成项目与线路错误。"
    if custom:
        text += " 当前为自定义档位，指纹匹配度仅供参考。"
    return text


def build_overall_verdict(
    *,
    juice_summary: dict[str, Any],
    fingerprint_summary: dict[str, Any] | None = None,
    output_integrity_summary: dict[str, Any] | None = None,
    coverage_summary: dict[str, Any] | None = None,
    fingerprint_enabled: bool = True,
    preset: str = "low",
    official: bool | None = None,
    custom_changes: list[str] | None = None,
    session_id: str | None = None,
    claimed_model: str = "gpt-5.6-sol",
) -> dict[str, Any]:
    fingerprint = fingerprint_summary or {}
    output = output_integrity_summary or {}
    coverage = coverage_summary or {}
    is_official = bool(official if official is not None else preset != "custom")
    custom = not is_official
    reasons = list(fingerprint.get("fingerprint_unclear_reasons") or [])
    if custom and "custom_probe_reference_only" not in reasons:
        reasons.append("custom_probe_reference_only")
    if not fingerprint_enabled and "builtin_fingerprint_not_enabled" not in reasons:
        reasons.append("builtin_fingerprint_not_enabled")
    if custom or not fingerprint_enabled:
        fingerprint = {
            **fingerprint,
            "fingerprint_status": "unclear",
            "fingerprint_model": None,
            "fingerprint_official_eligible": False,
        }
    fingerprint["fingerprint_unclear_reasons"] = reasons
    fingerprint["fingerprint_unclear_reasons_cn"] = [
        FINGERPRINT_REASON_CN.get(reason, "指纹层出现未分类的数据问题，请查看技术 JSON。")
        for reason in reasons
    ]

    juice_state = _juice_state(juice_summary, output, coverage)
    outcome_code, title = _title(juice_state, fingerprint)
    if outcome_code not in OUTCOME_CODES:
        raise AssertionError("verdict escaped the seven-outcome set")

    failed_items: list[dict[str, Any]] = []
    for event in juice_summary.get("sticky_events", []):
        failed_items.append({
            "layer": "Juice",
            "reason_code": "known_model_fingerprint_mismatch",
            "reason_cn": "检测到与申报型号不一致的已知 Juice 指纹。",
            "evidence": event.get("evidence"),
        })
    for row in output.get("failures", []):
        failed_items.append({
            "layer": "输出完整性",
            "reason_code": "output_rewritten_to_40",
            "reason_cn": "32/48 控制输出被改写为40或40开头的纯数字。",
            "evidence": row,
        })
    for row in coverage.get("failures", []):
        failed_items.append({
            "layer": "Juice覆盖检测",
            "reason_code": "explicit_definition_ignored",
            "reason_cn": "显式 Juice 定义可能被隐藏提示覆盖。",
            "evidence": row,
        })
    for reason, reason_cn in zip(
        fingerprint.get("fingerprint_unclear_reasons") or [],
        fingerprint.get("fingerprint_unclear_reasons_cn") or [],
    ):
        failed_item = {
            "layer": "指纹匹配",
            "reason_code": reason,
            "reason_cn": reason_cn,
        }
        if reason == "candidate_samples_incomplete":
            failed_item["incomplete_cells"] = [
                {"cell": key, **value}
                for key, value in (fingerprint.get("fingerprint_completeness") or {}).items()
                if not value.get("complete")
            ]
        failed_items.append(failed_item)
    if juice_summary.get("data_insufficient"):
        failed_items.append({
            "layer": "Juice",
            "reason_code": "juice_data_incomplete",
            "reason_cn": "至少一个启用思考档没有取得申报型号命中。",
            "missing_current_success_efforts": juice_summary.get("missing_current_success_efforts", []),
            "insufficient_valid_efforts": juice_summary.get("insufficient_valid_efforts", []),
        })

    common_causes: list[str] = []
    if juice_state == "possible_non_gpt":
        common_causes.extend(["待测端可能不是已知GPT模型", "输出被统一改写", "思考参数未透传", "探针被拦截"])
    if juice_state == "mismatch":
        common_causes.extend(["请求被路由到其他型号", "输出改写", "隐藏提示覆盖显式定义", "少量请求发生临时路由漂移"])
    if fingerprint.get("fingerprint_status") == "strong_match":
        common_causes.extend(["当前行为分布接近对应可信型号", "官方风控或临时路由也可能改变行为分布"])
    elif "builtin_fingerprint_not_enabled" in reasons:
        common_causes.extend(["当前为低档，未启用内置行为指纹探针", "这一层主动不给出型号方向，不代表模型或线路异常"])
    elif reasons:
        common_causes.extend(["模型行为落在强指向线以下", "网络错误或缺样", "题面或请求格式不受正式基线支持"])

    fingerprint_rows = _fingerprint_rows(fingerprint)
    return {
        "overall_verdict": title,
        "outcome_code": outcome_code,
        "verdict_available": True,
        "operational_status": "complete",
        "title_cn": title + ("（自定义参考）" if custom else ""),
        "subtitle_cn": _subtitle(juice_state, fingerprint, custom),
        "preset": preset,
        "custom_preset": custom,
        "official_grade": is_official,
        "trust_scope": "official_preset" if is_official else "advisory_only",
        "custom_changes": list(custom_changes or []),
        "session_id": session_id,
        "claimed_model": claimed_model,
        "juice_verdict_state": juice_state,
        "fingerprint_verdict_state": fingerprint.get("fingerprint_status", "unclear"),
        "fingerprint_model": fingerprint.get("fingerprint_model"),
        "failed_items": failed_items,
        "common_causes": sorted(set(common_causes)),
        "possible_models": fingerprint_rows,
        "fingerprint_details": fingerprint_rows,
        "juice_state": juice_summary.get("state"),
        "juice_quality_warning": bool(juice_summary.get("quality_warning")),
        "quality_note": "Juice 身份判定通过，但有效命中质量偏低" if juice_summary.get("quality_warning") else None,
        "limitations": [
            "指纹匹配度只比较已导入的Sol/Terra/Luna可信答案分布，不是真实路由概率",
            "自定义档位测试结果仅供参考" if custom else "网络错误不计入Juice有效响应",
        ],
    }


__all__ = ["FINGERPRINT_REASON_CN", "MODEL_LABELS", "OUTCOME_CODES", "build_overall_verdict"]
