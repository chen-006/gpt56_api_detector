#!/usr/bin/env python3
"""Render a concise, standalone HTML view for GPT-5.6 detector reports."""

from __future__ import annotations

from html import escape
import json
from pathlib import Path
from typing import Any


EFFORT_LABELS = {
    "low": "低档",
    "medium": "中档",
    "high": "高档",
    "xhigh": "超高档",
    "max": "最高档",
}


def _text(value: Any, default: str = "-") -> str:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return "是" if value else "否"
    return str(value)


def _e(value: Any, default: str = "-") -> str:
    return escape(_text(value, default), quote=True)


def _status_tone(status: str) -> str:
    lowered = status.casefold()
    if any(word in lowered for word in ("mixed", "invalid", "mismatch", "conflict", "rewrite", "not_compatible")):
        return "danger"
    if any(word in lowered for word in ("compatible_and", "variant_consistent", "healthy", "no_rewrite", "smooth")):
        return "success"
    if any(word in lowered for word in ("collect", "warming", "inconclusive", "intermittent", "unavailable", "unstable")):
        return "warning"
    return "neutral"


def _effort_rows(juice: dict[str, Any], *, single: bool = False) -> str:
    stats = juice.get("effort_stats", {})
    rows = []
    for effort in ("low", "medium", "high", "xhigh", "max"):
        item = stats.get(effort, {})
        rows.append(
            "<tr>"
            f"<th>{EFFORT_LABELS[effort]}</th>"
            f"<td>{_e(item.get('pass_count', 0))}</td>"
            f"<td>{_e(item.get('numeric_samples', 0))}</td>"
            f"<td>{_e(item.get('observations', 0)) if single else _e(item.get('observations', 0)) + ' / ' + _e(item.get('window_limit', 0))}</td>"
            "</tr>"
        )
    return "".join(rows)


def _alerts(report: dict[str, Any]) -> list[str]:
    alerts: list[str] = []
    combined = report.get("combined_summary", {})
    juice = report.get("juice_summary", {})
    control = report.get("output_literal_control_summary") or {}
    health = report.get("monitor_health_summary", {})
    rolling = report.get("rolling_summary", report.get("summary", {}))
    if combined.get("passed_cn") == "不通过":
        alerts.append(combined.get("title_cn", "检测未通过"))
    if juice.get("status") == "mixed_or_inconsistent":
        alerts.append("Juice 型号结果出现互斥指纹，当前会话已标记混用")
    if control.get("status") == "output_rewrite_suspected":
        latest = (control.get("session_anomalies") or [{}])[-1]
        alerts.append(
            "高档字面量输出异常：要求 "
            f"{_text(latest.get('expected_text'))}，实际得到 "
            f"{_text(latest.get('observed_text'))}"
        )
    if health.get("current_monitoring_effective") is False:
        alerts.append(health.get("title_cn", "当前监控未有效刷新"))
    negative = int(rolling.get("message_only_exact", rolling.get("candidate_message_only_exact", 0)) or 0)
    negative += int(rolling.get("corrupted_ciphertext_exact", rolling.get("candidate_corrupted_ciphertext_exact", 0)) or 0)
    leaks = int(rolling.get("plaintext_leaks", rolling.get("candidate_request_plaintext_leaks", 0)) or 0)
    if negative:
        alerts.append(f"阴性对照出现 {negative} 次异常命中")
    if leaks:
        alerts.append(f"检测到 {leaks} 次答案明文泄漏")
    return alerts


def _iter_request_metadata(value: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if any(key in value for key in ("correlation_id", "server_request_id", "token_usage")):
            found.append(value)
        for child in value.values():
            found.extend(_iter_request_metadata(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(_iter_request_metadata(child))
    return found


def _metadata_section(report: dict[str, Any]) -> str:
    configuration = report.get("configuration", {})
    options = configuration.get("request_metadata", {})
    observations = _iter_request_metadata(report)[-30:]
    rows: list[str] = []
    for item in observations:
        usage = item.get("token_usage") or {}
        token_text = "-"
        if isinstance(usage, dict):
            source = "estimated" if usage.get("source") == "estimated" else "usage"
            token_text = f"{source}: {_text(usage.get('total_tokens'))}"
        request_id = (
            item.get("server_request_id")
            or item.get("response_id")
            or item.get("correlation_id")
        )
        ip_text = item.get("client_egress_ip") or "-"
        server_ips = item.get("server_ips") or []
        if server_ips:
            ip_text = f"{ip_text} / {', '.join(map(str, server_ips))}"
        rows.append(
            "<tr>"
            f"<td>{_e(request_id)}</td><td>{_e(item.get('started_at'))}</td>"
            f"<td>{_e(item.get('http_status'))}</td><td>{_e(item.get('elapsed_ms'))}</td>"
            f"<td>{_e(token_text)}</td><td>{_e(ip_text)}</td>"
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="6" class="muted">未收集到请求级元数据</td></tr>')
    estimate_note = options.get("token_estimate_warning")
    note = f"<p class=\"muted\">{_e(estimate_note)}</p>" if estimate_note else ""
    enabled = ", ".join(
        key for key, value in options.items() if key.startswith("include_") and value
    ) or "仅默认安全字段"
    return (
        '<section class="band"><h2>请求级详细信息</h2>'
        f"<p class=\"muted\">已启用：{_e(enabled)}</p>{note}"
        '<table class="metadata-table"><thead><tr>'
        "<th>Request ID</th><th>开始时间</th><th>HTTP</th><th>耗时(ms)</th>"
        "<th>Token</th><th>客户端出口 IP / 服务端 DNS IP</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></section>"
    )


def render_report_html(report: dict[str, Any]) -> str:
    combined = report.get("combined_summary", {})
    juice = report.get("juice_summary", {})
    control = report.get("output_literal_control_summary") or {}
    network = report.get("network_summary", {})
    health = report.get("monitor_health_summary", {})
    rolling = report.get("rolling_summary", report.get("summary", {}))
    configuration = report.get("configuration", {})
    mode = configuration.get("detection_mode", report.get("mode", "unknown"))
    juice_only = mode == "juice_only" or "juice_only" in str(report.get("mode", ""))
    single = "_single_v3_1_1" in str(report.get("mode", ""))
    combined_status = str(combined.get("status", report.get("combined_verdict", "unknown")))
    tone = _status_tone(combined_status)
    alerts = _alerts(report)
    alert_html = "".join(f"<li>{escape(item)}</li>" for item in alerts)
    if not alert_html:
        alert_html = "<li class=\"ok\">当前没有检测到需要立即处理的异常</li>"

    full_exact = rolling.get("full_exact", rolling.get("candidate_full_exact", 0))
    without_ids = rolling.get("without_ids_exact", rolling.get("candidate_without_ids_exact", 0))
    required = rolling.get("required_positive_matches", configuration.get("required_matches_per_positive_condition", 0))
    attempts = rolling.get("candidate_attempts_in_window", rolling.get("candidate_attempts", 0))
    window_size = rolling.get("window_size", configuration.get("rolling_window", attempts))
    negatives = int(rolling.get("message_only_exact", rolling.get("candidate_message_only_exact", 0)) or 0)
    negatives += int(rolling.get("corrupted_ciphertext_exact", rolling.get("candidate_corrupted_ciphertext_exact", 0)) or 0)
    leaks = rolling.get("plaintext_leaks", rolling.get("candidate_request_plaintext_leaks", 0))

    control_counts = control.get("expected_counts", {})
    control_exact = control.get("exact_by_expected", {})
    if single:
        summary = report.get("summary", {})
        attempts = summary.get("candidate_attempts", summary.get("valid_trials", 0))
        window_size = configuration.get("requested_candidate_attempts", attempts)
        full_exact = summary.get("candidate_full_exact", full_exact)
        without_ids = summary.get("candidate_without_ids_exact", without_ids)
        required = configuration.get("required_matches_per_positive_condition", required)
        strong_body = (
            "<div class=\"metrics\">"
            f"<div><span>本次样本</span><strong>{_e(attempts)} / {_e(window_size)}</strong></div>"
            f"<div><span>完整状态</span><strong>{_e(full_exact)} / {_e(required)}</strong></div>"
            f"<div><span>去掉编号</span><strong>{_e(without_ids)} / {_e(required)}</strong></div>"
            f"<div><span>阴性异常</span><strong>{_e(negatives)}</strong></div>"
            f"<div><span>明文泄漏</span><strong>{_e(leaks)}</strong></div>"
            "</div>"
        )
    else:
        strong_body = (
        "<p class=\"muted\">当前为 Juice-only 模式，未执行加密状态能力挑战。</p>"
        if juice_only
        else (
            "<div class=\"metrics\">"
            f"<div><span>窗口</span><strong>{_e(attempts)} / {_e(window_size)}</strong></div>"
            f"<div><span>完整状态</span><strong>{_e(full_exact)} / {_e(required)}</strong></div>"
            f"<div><span>去掉编号</span><strong>{_e(without_ids)} / {_e(required)}</strong></div>"
            f"<div><span>阴性异常</span><strong>{_e(negatives)}</strong></div>"
            f"<div><span>明文泄漏</span><strong>{_e(leaks)}</strong></div>"
            "</div>"
        )
        )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GPT-5.6 检测报告</title>
<style>
:root {{ color-scheme: light; --bg:#f4f6f8; --ink:#17202a; --muted:#66717e; --line:#d9dee5; --panel:#fff; --success:#16784a; --warning:#9a6500; --danger:#b42318; --neutral:#52606d; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:14px/1.55 "Segoe UI","Microsoft YaHei",sans-serif; letter-spacing:0; }}
header {{ background:#18252f; color:#fff; padding:24px max(24px,calc((100vw - 1080px)/2)); }}
header h1 {{ margin:0 0 6px; font-size:24px; font-weight:650; }}
header p {{ margin:0; color:#cbd4dc; }}
main {{ max-width:1080px; margin:0 auto; padding:24px; }}
.verdict {{ border-left:5px solid var(--neutral); background:var(--panel); padding:18px 20px; margin-bottom:18px; }}
.verdict.success {{ border-color:var(--success); }} .verdict.warning {{ border-color:var(--warning); }} .verdict.danger {{ border-color:var(--danger); }}
.verdict h2 {{ margin:0 0 4px; font-size:20px; }} .verdict p {{ margin:4px 0 0; }}
.band {{ background:var(--panel); border:1px solid var(--line); margin:0 0 16px; padding:18px 20px; border-radius:6px; }}
.band h2 {{ font-size:16px; margin:0 0 14px; }}
.grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px; }}
.metrics {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:10px; }}
.metrics div {{ border-top:2px solid #ccd3da; padding:10px 2px; }} .metrics span {{ display:block; color:var(--muted); font-size:12px; }} .metrics strong {{ font-size:17px; }}
table {{ width:100%; border-collapse:collapse; }} th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }} th {{ font-weight:600; }}
ul {{ margin:0; padding-left:20px; }} li {{ margin:5px 0; }} li.ok {{ color:var(--success); }}
.pill {{ display:inline-block; border:1px solid currentColor; border-radius:999px; padding:2px 8px; font-size:12px; }}
.success-text {{ color:var(--success); }} .warning-text {{ color:var(--warning); }} .danger-text {{ color:var(--danger); }} .muted {{ color:var(--muted); }}
.footer {{ color:var(--muted); font-size:12px; margin-top:18px; }}
.metadata-table {{ font-size:12px; }}
@media (max-width:720px) {{ .grid,.metrics {{ grid-template-columns:1fr; }} main {{ padding:14px; }} }}
</style>
</head>
<body>
<header><h1>GPT-5.6 检测报告</h1><p>更新时间 {_e(report.get('updated_at', report.get('created_at')))} · 模式 {_e(mode)}</p></header>
<main>
<section class="verdict {tone}">
  <span class="pill">{_e(combined.get('passed_cn', '状态'))}</span>
  <h2>{_e(combined.get('title_cn', combined_status))}</h2>
  <p>{_e(combined.get('explanation_cn', report.get('reason')))}</p>
</section>
<section class="band"><h2>需要关注</h2><ul>{alert_html}</ul></section>
<div class="grid">
  <section class="band"><h2>监控健康度</h2>
    <div class="metrics">
      <div><span>状态</span><strong>{_e('单次结果' if single else health.get('title_cn', health.get('status')))}</strong></div>
      <div><span>当前有效</span><strong>{_e('-' if single else health.get('current_monitoring_effective'))}</strong></div>
      <div><span>连续失败</span><strong>{_e('-' if single else health.get('consecutive_trusted_failures', health.get('consecutive_candidate_failures', 0)))}</strong></div>
    </div>
    <p class="muted">{_e(health.get('detail_cn'))}</p>
  </section>
  <section class="band"><h2>线路质量</h2>
    <div class="metrics">
      <div><span>状态</span><strong>{_e(network.get('title_cn', network.get('status')))}</strong></div>
      <div><span>错误轮次</span><strong>{_e(rolling.get('candidate_error_rounds', 0))}</strong></div>
      <div><span>重试轮次</span><strong>{_e(rolling.get('candidate_retry_rounds', 0))}</strong></div>
    </div>
    <p class="muted">{_e(network.get('detail_cn'))}</p>
  </section>
</div>
<section class="band"><h2>加密状态能力</h2>{strong_body}</section>
<section class="band"><h2>Juice 型号指纹</h2>
  <p><strong>{_e(juice.get('likely_model_cn'))}</strong> · 置信度 {_e(juice.get('confidence'))} · 混用 {_e(juice.get('status') == 'mixed_or_inconsistent')}</p>
  <table><thead><tr><th>档位</th><th>通过</th><th>有效数字</th><th>{'本次样本' if single else '滚动窗口'}</th></tr></thead><tbody>{_effort_rows(juice, single=single)}</tbody></table>
</section>
<section class="band"><h2>高档字面量输出完整性</h2>
  <div class="metrics">
    <div><span>状态</span><strong>{_e(control.get('title_cn', control.get('status')))}</strong></div>
    <div><span>Luna 48</span><strong>{_e(control_exact.get('48', 0))} / {_e(control_counts.get('48', 0))}</strong></div>
    <div><span>Terra 32</span><strong>{_e(control_exact.get('32', 0))} / {_e(control_counts.get('32', 0))}</strong></div>
    <div><span>非预期</span><strong>{_e(control.get('non_exact_successes', 0))}</strong></div>
    <div><span>会话异常</span><strong>{_e(control.get('session_non_exact_successes', 0))}</strong></div>
    <div><span>请求错误</span><strong>{_e(control.get('errors', 0))}</strong></div>
  </div>
</section>
<p class="footer">加密状态层不能区分 Sol、Terra、Luna；Juice 与字面量输出对照均为可伪造的辅助证据。综合通过不能排除透明代理、探针识别或普通请求差异化路由。</p>
{_metadata_section(report)}
</main>
</body>
</html>"""


def write_report_html(report: dict[str, Any], json_path: Path) -> Path:
    html_path = json_path.with_suffix(".html")
    temporary = html_path.with_suffix(".html.tmp")
    temporary.write_text(render_report_html(report), encoding="utf-8")
    temporary.replace(html_path)
    return html_path


def convert_json_report(json_path: Path) -> Path:
    report = json.loads(json_path.read_text(encoding="utf-8"))
    return write_report_html(report, json_path)
