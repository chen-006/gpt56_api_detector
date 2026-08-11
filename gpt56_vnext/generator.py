from __future__ import annotations

from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import threading
import time
from typing import Any, Callable
import uuid

from .normalizers import normalize_answer, validate_normalizer
from .probability_model import MODELS, fit_baseline, fit_cell, verify_baseline
from .store import SQLiteStateStore
from .transport import RequestCancellationController, TransportCancelled, TransportError
from .utils import atomic_write_json, canonical_json, deterministic_job_id, sha256_text, utc_now


@dataclass
class GeneratorPlan:
    name: str
    probe_id: str
    user_prompt: str
    model_names: dict[str, str] = field(default_factory=lambda: {model: model for model in MODELS})
    effort: str = "low"
    samples_per_model: int = 100
    runtime_samples: int = 10
    developer_prompt: str = ""
    request_formats: tuple[str, ...] = ("normal",)
    context_modes: tuple[str, ...] = ("no_history",)
    normalizer: dict[str, Any] = field(default_factory=lambda: {"id": "exact_trimmed_casefold", "parameters": {}})
    temporal_windows: int = 1
    window_gap_seconds: int = 900
    workers: int = 20
    retries: int = 2
    description: str = ""
    tags: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.name.strip() or not self.probe_id.strip() or not self.user_prompt.strip():
            raise ValueError("name, probe_id, and user_prompt are required")
        if not all(character.isalnum() or character in "-_" for character in self.probe_id):
            raise ValueError("probe_id may contain only letters, digits, hyphen, and underscore")
        if self.effort not in {"none", "minimal", "low", "medium", "high", "xhigh", "max"}:
            raise ValueError("unsupported reasoning effort")
        if not 1 <= self.samples_per_model <= 10000:
            raise ValueError("samples_per_model must be 1-10000")
        if not 1 <= self.runtime_samples <= self.samples_per_model:
            raise ValueError("runtime_samples must be positive and no larger than samples_per_model")
        if not 1 <= self.temporal_windows <= 12:
            raise ValueError("temporal_windows must be 1-12")
        if not 1 <= self.workers <= 32:
            raise ValueError("workers must be 1-32")
        if not 0 <= self.retries <= 2:
            raise ValueError("retries must be 0-2")
        if not self.request_formats or any(value not in {"normal", "native_codex"} for value in self.request_formats):
            raise ValueError("invalid request_formats")
        if not self.context_modes or any(value not in {"no_history", "fixed_32k_history"} for value in self.context_modes):
            raise ValueError("invalid context_modes")
        if set(self.model_names) != set(MODELS) or any(not str(value).strip() for value in self.model_names.values()):
            raise ValueError("all three trusted model names are required")
        validate_normalizer(self.normalizer)

    def jobs(self) -> list[dict[str, Any]]:
        self.validate()
        per_window = [self.samples_per_model // self.temporal_windows] * self.temporal_windows
        for index in range(self.samples_per_model % self.temporal_windows):
            per_window[index] += 1
        jobs: list[dict[str, Any]] = []
        for window, count in enumerate(per_window, start=1):
            for model in MODELS:
                for request_format in self.request_formats:
                    for context_mode in self.context_modes:
                        for sample_index in range(1, count + 1):
                            fields = {
                                "probe_id": self.probe_id,
                                "window": window,
                                "cycle": window,
                                "model": model,
                                "request_format": request_format,
                                "context_mode": context_mode,
                                "effort": self.effort,
                                "sample_index": sample_index,
                            }
                            jobs.append({
                                **fields,
                                "job_id": deterministic_job_id(fields),
                                "upstream_model": self.model_names[model],
                            })
        return jobs

    def to_public_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "name": self.name,
            "probe_id": self.probe_id,
            "user_prompt": self.user_prompt,
            "developer_prompt": self.developer_prompt,
            "effort": self.effort,
            "model_names": dict(self.model_names),
            "samples_per_model": self.samples_per_model,
            "runtime_samples": self.runtime_samples,
            "request_formats": list(self.request_formats),
            "context_modes": list(self.context_modes),
            "normalizer": self.normalizer,
            "temporal_windows": self.temporal_windows,
            "window_gap_seconds": self.window_gap_seconds,
            "workers": self.workers,
            "retries": self.retries,
            "description": self.description,
            "tags": list(self.tags),
        }


RequestCallable = Callable[[dict[str, Any], list[dict[str, str]]], dict[str, Any]]
CANCELLATION_POLL_SECONDS = 0.10
CANCELLATION_GRACE_SECONDS = 3.0


class ProbeGeneratorSession:
    def __init__(
        self,
        plan: GeneratorPlan,
        directory: str | Path,
        *,
        session_id: str | None = None,
        safe_endpoint: str | None = None,
        activate: bool = True,
    ):
        plan.validate()
        self.plan = plan
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.store = SQLiteStateStore(self.directory / "state.sqlite3")
        self.session_id = session_id or uuid.uuid4().hex
        plan_value = plan.to_public_dict()
        plan_hash = hashlib.sha256(canonical_json(plan_value).encode("utf-8")).hexdigest()
        self.store.create_session(
            session_id=self.session_id,
            kind="generator",
            status="running",
            config=plan_value,
            config_hash=plan_hash,
            official=False,
            safe_endpoint=safe_endpoint,
        )
        if session_id and activate:
            self.store.update_session_status(self.session_id, "running", clear_stop=True)
        if activate:
            self.store.reconcile_incomplete_attempts(self.session_id, self.plan.retries + 1)
        self.stop_event = threading.Event()
        self.cancellation = RequestCancellationController()
        self._fatal_error: dict[str, Any] | None = None
        self._fatal_lock = threading.Lock()
        self.output_path: Path | None = None

    def close(self) -> None:
        self.store.close()

    def stop(self) -> dict[str, Any]:
        previous = self.store.session(self.session_id) or {}
        previous_status = str(previous.get("status") or "unknown")
        self.stop_event.set()
        requested_at = self.store.request_stop(self.session_id)
        self.store.update_session_status(self.session_id, "stopping")
        cancelled = self.cancellation.cancel_all()
        return {
            "accepted": True,
            "session_id": self.session_id,
            "previous_status": previous_status,
            "current_status": "stopping",
            "stop_requested_at": requested_at,
            "active_requests_cancelled": cancelled,
        }

    def _stop_for_auth_error(self, status: int | None) -> None:
        with self._fatal_lock:
            if self._fatal_error is None:
                self._fatal_error = {
                    "category": "upstream_authentication_failed",
                    "http_status": status,
                    "safe_message": f"可信 API 认证失败（HTTP {status}），已停止后续采样请求",
                }
        self.stop_event.set()
        self.cancellation.cancel_all()

    def progress_snapshot(self) -> dict[str, Any]:
        progress = self.store.progress(self.session_id)
        progress["remaining"] = max(0, progress["planned"] - progress["logical_completed"])
        return progress

    def run(self, request: RequestCallable) -> dict[str, Any]:
        all_jobs = self.plan.jobs()
        by_window: dict[int, list[dict[str, Any]]] = {}
        for job in all_jobs:
            by_window.setdefault(int(job["window"]), []).append(job)
        for window in sorted(by_window):
            if self.stop_event.is_set():
                break
            frozen = self.store.frozen_jobs(self.session_id, window)
            jobs = frozen or self.store.freeze_jobs(self.session_id, window, by_window[window])
            if frozen:
                self.store.append_event(self.session_id, "window_resume", cycle=window, payload={"planned_jobs": len(jobs)})
            else:
                self.store.append_event(self.session_id, "window_start", cycle=window, payload={"planned_jobs": len(jobs)})
            self._run_jobs(jobs, request)
            if self.stop_event.is_set():
                break
            pending = [job for job in self.store.pending_jobs(self.session_id, window, max_attempts=self.plan.retries + 1)]
            if pending:
                break
            self.store.append_event(self.session_id, "window_end", cycle=window, payload={"planned_jobs": len(jobs)})
            if window < max(by_window) and self.plan.window_gap_seconds > 0:
                self.stop_event.wait(self.plan.window_gap_seconds)
        progress = self.progress_snapshot()
        if self._fatal_error is not None:
            final_status = "error"
            error = self._fatal_error["safe_message"]
        elif self.stop_event.is_set():
            final_status = "stopped"
            error = None
        elif progress["planned"] > 0 and progress["successful"] == 0:
            final_status = "error"
            error = "没有取得任何有效样本，请检查可信 API 地址、权限和线路"
        else:
            final_status = "collected"
            error = None
        if error:
            self.store.append_event(
                self.session_id,
                "generator_error",
                payload={"safe_message": error, "fatal": self._fatal_error is not None},
            )
        self.store.update_session_status(self.session_id, final_status)
        return {**progress, "status": final_status, "error": error}

    def _run_jobs(self, jobs: list[dict[str, Any]], request: RequestCallable) -> None:
        ids = {job["job_id"] for job in jobs}
        pending = [
            job for job in self.store.pending_jobs(self.session_id, max_attempts=self.plan.retries + 1)
            if job["job_id"] in ids
        ]
        if not pending:
            return
        iterator = iter(pending)
        workers = max(1, min(self.plan.workers, len(pending)))
        executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="gpt56-generator")
        futures: dict[Any, dict[str, Any]] = {}
        cancellation_deadline: float | None = None

        def submit_next() -> bool:
            if self.stop_event.is_set():
                return False
            try:
                job = next(iterator)
            except StopIteration:
                return False
            futures[executor.submit(self._execute_job, job, request)] = job
            return True

        try:
            for _ in range(workers):
                submit_next()
            while futures:
                done, _ = wait(
                    tuple(futures),
                    timeout=CANCELLATION_POLL_SECONDS,
                    return_when=FIRST_COMPLETED,
                )
                if not done:
                    if self.stop_event.is_set():
                        if cancellation_deadline is None:
                            self.cancellation.cancel_all()
                            cancellation_deadline = time.monotonic() + CANCELLATION_GRACE_SECONDS
                        if time.monotonic() >= cancellation_deadline:
                            break
                    continue
                for future in done:
                    futures.pop(future)
                    future.result()
                    submit_next()
        finally:
            active_job_ids = {str(job["job_id"]) for job in futures.values()}
            if self.stop_event.is_set():
                self.cancellation.cancel_all()
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False, cancel_futures=True)
            if self.stop_event.is_set():
                for job in self.store.pending_jobs(self.session_id, max_attempts=self.plan.retries + 1):
                    if job["job_id"] not in ids:
                        continue
                    attempts_sent = self.store.next_attempt_number(self.session_id, job["job_id"]) - 1
                    category = (
                        "cancelled_before_send" if attempts_sent == 0
                        else "cancelled_in_flight" if job["job_id"] in active_job_ids
                        else "cancelled_before_retry"
                    )
                    self.store.record_cancelled(
                        self.session_id,
                        job["job_id"],
                        self._cancelled_row(job, attempts_sent, category),
                    )
                self.store.cancel_running_attempts(
                    self.session_id,
                    active_job_ids,
                    category="cancelled_in_flight",
                )

    @staticmethod
    def _cancelled_row(job: dict[str, Any], attempts_sent: int, category: str) -> dict[str, Any]:
        return {
            **job,
            "kind": "behavior",
            "status": "cancelled",
            "time": utc_now(),
            "attempts_sent": attempts_sent,
            "error": {
                "stage": "transport",
                "category": category,
                "retryable": False,
                "http_status": None,
                "attempt": attempts_sent,
                "safe_message": "用户已停止采集，当前请求已取消",
            },
        }

    def _execute_job(self, job: dict[str, Any], request: RequestCallable) -> dict[str, Any]:
        messages = []
        if self.plan.developer_prompt:
            messages.append({"role": "developer", "content": self.plan.developer_prompt})
        messages.append({"role": "user", "content": self.plan.user_prompt})
        max_attempts = self.plan.retries + 1
        first_attempt = self.store.next_attempt_number(self.session_id, job["job_id"])
        for attempt_no in range(first_attempt, max_attempts + 1):
            if self.stop_event.is_set():
                row = self._cancelled_row(job, attempt_no - 1, "cancelled_before_retry")
                self.store.record_cancelled(self.session_id, job["job_id"], row)
                return row
            attempt_id = self.store.start_attempt(self.session_id, job["job_id"], attempt_no, max_attempts=max_attempts)
            try:
                result = request(job, messages)
                if self.stop_event.is_set():
                    raise TransportCancelled()
                answer = str(result.get("answer", ""))
                row = {
                    **job,
                    "kind": "behavior",
                    "time": utc_now(),
                    "status": "ok",
                    "normalized_value": normalize_answer(answer, self.plan.normalizer),
                    "answer_sha256": sha256_text(answer),
                    "answer_length": len(answer),
                    "streaming": bool(result.get("streaming", True)),
                    "http_status": result.get("http_status", 200),
                    "usage": result.get("usage"),
                    "attempts_sent": attempt_no,
                }
                self.store.finish_attempt(
                    attempt_id=attempt_id,
                    status="ok",
                    stage="response",
                    category="ok",
                    retryable=False,
                    http_status=row["http_status"],
                    safe_message="ok",
                    final_result=row,
                    final_job_status="ok",
                )
                return row
            except TransportCancelled:
                row = self._cancelled_row(job, attempt_no, "cancelled_in_flight")
                self.store.finish_attempt(
                    attempt_id=attempt_id,
                    status="cancelled",
                    stage="transport",
                    category="cancelled_in_flight",
                    retryable=False,
                    http_status=None,
                    safe_message=row["error"]["safe_message"],
                    final_result=row,
                    final_job_status="cancelled",
                )
                return row
            except Exception as exc:
                status = getattr(exc, "status", None)
                if isinstance(exc, TransportError) and status in {401, 403}:
                    self._stop_for_auth_error(status)
                retryable = isinstance(exc, TransportError) and exc.retryable
                will_retry = retryable and attempt_no < max_attempts and not self.stop_event.is_set()
                final = None if will_retry else {
                    **job,
                    "kind": "behavior",
                    "time": utc_now(),
                    "status": "error",
                    "attempts_sent": attempt_no,
                    "error": exc.error_info(attempt_no) if isinstance(exc, TransportError) else {
                        "stage": "local_processing", "category": type(exc).__name__, "retryable": False,
                        "http_status": status, "safe_message": f"本地处理失败：{type(exc).__name__}",
                    },
                }
                self.store.finish_attempt(
                    attempt_id=attempt_id,
                    status="error",
                    stage=exc.stage if isinstance(exc, TransportError) else "local_processing",
                    category=exc.category if isinstance(exc, TransportError) else type(exc).__name__,
                    retryable=will_retry,
                    http_status=status,
                    safe_message=final["error"]["safe_message"] if final else "可重试传输错误",
                    final_result=final,
                    final_job_status="error" if final else None,
                )
                if not will_retry:
                    return final or {}
                self.stop_event.wait(min(2.0, 0.25 * (2 ** (attempt_no - 1))))
        raise AssertionError("attempt loop exhausted")

    def _raw_baseline(self) -> dict[str, Any]:
        profiles: dict[str, Any] = {}
        rows = self.store.latest_results(self.session_id)
        for request_format in self.plan.request_formats:
            for context_mode in self.plan.context_modes:
                profile_name = f"{request_format}+{context_mode}"
                models: dict[str, Any] = {}
                for model in MODELS:
                    windows: dict[str, Any] = {}
                    for window in range(1, self.plan.temporal_windows + 1):
                        values = [
                            row for row in rows
                            if row.get("status") == "ok"
                            and row.get("model") == model
                            and row.get("request_format") == request_format
                            and row.get("context_mode") == context_mode
                            and int(row.get("window", 0)) == window
                        ]
                        counts = Counter(str(row.get("normalized_value") or "__INVALID_OUTPUT__") for row in values)
                        windows[str(window)] = {
                            "counts": dict(counts),
                            "total": len(values),
                            "valid": sum(key != "__INVALID_OUTPUT__" for key in counts.elements()),
                        }
                    models[model] = {"windows": windows}
                profiles[profile_name] = {"models": models, "windows": list(range(1, self.plan.temporal_windows + 1))}
        return {"baseline_id": f"custom-{self.plan.probe_id}", "probes": {self.plan.probe_id: {"profiles": profiles}}}

    def analyze_and_export(self, output_path: str | Path) -> dict[str, Any]:
        raw = self._raw_baseline()
        runtime_spec = {
            "name": f"custom:{self.plan.probe_id}",
            "cells": {
                f"{self.plan.probe_id}|{request_format}+{context_mode}": self.plan.runtime_samples
                for request_format in self.plan.request_formats
                for context_mode in self.plan.context_modes
            },
            "contracts": {},
        }
        metadata = {
            self.plan.probe_id: {
                "name": self.plan.name,
                "description": self.plan.description,
                "tags": list(self.plan.tags),
                "user_prompt": self.plan.user_prompt,
                "user_prompt_sha256": sha256_text(self.plan.user_prompt),
                "developer_prompt": self.plan.developer_prompt,
                "developer_prompt_sha256": sha256_text(self.plan.developer_prompt),
                "effort": self.plan.effort,
                "normalizer": self.plan.normalizer,
                "normalizer_hash": sha256_text(canonical_json(self.plan.normalizer)),
            }
        }
        for key in runtime_spec["cells"]:
            _probe_id, profile_name = key.split("|", 1)
            request_format, context_mode = profile_name.split("+", 1)
            runtime_spec["contracts"][key] = {
                "probe_id": self.plan.probe_id,
                "profile": profile_name,
                "user_prompt_sha256": metadata[self.plan.probe_id]["user_prompt_sha256"],
                "developer_prompt_sha256": metadata[self.plan.probe_id]["developer_prompt_sha256"],
                "effort": self.plan.effort,
                "request_format": request_format,
                "context_mode": context_mode,
                "normalizer_hash": metadata[self.plan.probe_id]["normalizer_hash"],
            }
        baseline = fit_baseline(
            raw,
            runtime_specs=[runtime_spec],
            probe_metadata=metadata,
            baseline_id=f"custom-{self.plan.probe_id}",
        )
        baseline["reference_only_reason"] = (
            "自定义探针仅作为参考证据；单时间窗不能验证随时间稳定性。"
            if self.plan.temporal_windows == 1
            else "自定义探针仅作为参考证据；多个时间窗已用于估计时间漂移。"
        )
        baseline["time_stability_verified"] = self.plan.temporal_windows >= 2
        baseline.pop("content_sha256", None)
        baseline["content_sha256"] = sha256_text(canonical_json(baseline))
        export = {
            "schema_version": 3,
            "probe_identity": {
                "name": self.plan.name,
                "probe_id": self.plan.probe_id,
                "description": self.plan.description,
                "tags": list(self.plan.tags),
            },
            "exact_prompts_and_hashes": {
                "user_prompt": self.plan.user_prompt,
                "user_prompt_sha256": sha256_text(self.plan.user_prompt),
                "developer_prompt": self.plan.developer_prompt,
                "developer_prompt_sha256": sha256_text(self.plan.developer_prompt),
            },
            "profile": {
                "effort": self.plan.effort,
                "request_formats": list(self.plan.request_formats),
                "context_modes": list(self.plan.context_modes),
            },
            "normalizer": self.plan.normalizer,
            "runtime_requests": self.plan.runtime_samples,
            "time_windows": self.plan.temporal_windows,
            "formal_eligible": bool(baseline.get("formal_eligible")),
            "reference_ready": bool(baseline.get("reference_ready", baseline.get("formal_eligible"))),
            "baseline_artifact": baseline,
            "auth_values_persisted": False,
        }
        export["content_sha256"] = sha256_text(canonical_json(export))
        output = Path(output_path)
        atomic_write_json(output, export)
        self.output_path = output
        self.store.update_session_status(self.session_id, "complete")
        return export


def verify_probe_file(value: dict[str, Any]) -> None:
    forbidden = {"api_key", "authorization", "credential", "base_url", "endpoint_url"}

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                if str(key).casefold() in forbidden:
                    raise ValueError(f"forbidden field in probe file: {key}")
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    expected = str(value.get("content_sha256") or "")
    body = dict(value)
    body.pop("content_sha256", None)
    if expected != sha256_text(canonical_json(body)):
        raise ValueError("probe content hash mismatch")
    normalizer = value.get("normalizer") or {}
    validate_normalizer(normalizer)
    identity = value.get("probe_identity") or {}
    prompts = value.get("exact_prompts_and_hashes") or {}
    probe_id = str(identity.get("probe_id") or "")
    if not probe_id:
        raise ValueError("probe_id is required")
    if sha256_text(str(prompts.get("user_prompt") or "")) != str(prompts.get("user_prompt_sha256") or ""):
        raise ValueError("user prompt hash mismatch")
    if sha256_text(str(prompts.get("developer_prompt") or "")) != str(prompts.get("developer_prompt_sha256") or ""):
        raise ValueError("developer prompt hash mismatch")
    baseline = value.get("baseline_artifact")
    if baseline:
        verify_baseline(baseline)
        metadata = (baseline.get("probe_metadata") or {}).get(probe_id) or {}
        if str(metadata.get("user_prompt_sha256") or "") != str(prompts.get("user_prompt_sha256") or ""):
            raise ValueError("baseline user prompt contract mismatch")
        if str(metadata.get("developer_prompt_sha256") or "") != str(prompts.get("developer_prompt_sha256") or ""):
            raise ValueError("baseline developer prompt contract mismatch")
        if str(metadata.get("effort") or "") != str((value.get("profile") or {}).get("effort") or ""):
            raise ValueError("baseline effort contract mismatch")
        normalizer_hash = sha256_text(canonical_json(normalizer))
        if str(metadata.get("normalizer_hash") or "") != normalizer_hash:
            raise ValueError("baseline normalizer contract mismatch")
        if probe_id not in (baseline.get("raw_counts") or {}):
            raise ValueError("baseline probe data is missing")


def probe_document(value: dict[str, Any]) -> dict[str, Any]:
    """Return the immutable signed probe document from a runtime configuration."""
    raw_document = value.get("probe_file_json")
    if raw_document is not None:
        if not isinstance(raw_document, str):
            raise ValueError("custom probe_file_json must be text")
        try:
            document = json.loads(raw_document)
        except json.JSONDecodeError as exc:
            raise ValueError("custom probe_file_json is invalid JSON") from exc
        if not isinstance(document, dict):
            raise ValueError("custom probe_file_json must contain an object")
        return document
    document = value.get("probe_file")
    if document is None:
        return value
    if not isinstance(document, dict):
        raise ValueError("custom probe_file must be an object")
    return document


def wrap_probe_file(value: dict[str, Any]) -> dict[str, Any]:
    """Keep mutable detector settings outside the signed probe document."""
    verify_probe_file(value)
    return {
        "probe_file": value,
        "probe_file_json": json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False),
        "enabled": True,
        "runtime_requests": int(value.get("runtime_requests", 10)),
        "probability_percent": 100,
        "window": 20,
    }


def reference_baseline(value: dict[str, Any]) -> dict[str, Any]:
    """Materialize descriptive cells for older signed single-window probe files."""
    document = probe_document(value)
    artifact = deepcopy(document.get("baseline_artifact") or {})
    if artifact.get("cells"):
        return artifact
    cells: dict[str, Any] = {}
    for probe_id, probe in (artifact.get("raw_counts") or {}).items():
        for profile_name, profile in (probe.get("profiles") or {}).items():
            cells[f"{probe_id}|{profile_name}"] = fit_cell(profile)
    artifact["cells"] = cells
    artifact["runtime_cells_derived_from_signed_raw_counts"] = bool(cells)
    artifact.pop("content_sha256", None)
    artifact["content_sha256"] = sha256_text(canonical_json(artifact))
    return artifact


__all__ = [
    "GeneratorPlan",
    "ProbeGeneratorSession",
    "probe_document",
    "reference_baseline",
    "verify_probe_file",
    "wrap_probe_file",
]
