from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import mimetypes
from pathlib import Path
import re
import secrets
import sqlite3
import threading
from typing import Any
from urllib.parse import urlsplit

from .detector import DEFAULT_BASELINE, DetectorSession
from .generator import GeneratorPlan, ProbeGeneratorSession, probe_document, verify_probe_file, wrap_probe_file
from .presets import estimate_single_requests, normalize_config, preset_catalog
from .probability_model import load_baseline
from .retention import RetentionWriteError
from .store import SQLiteStateStore
from .transport import StreamingTransport
from .utils import canonical_json, normalize_api_base_url, utc_now


WEB_ROOT = Path(__file__).with_name("web")


def _probability_probe_catalog() -> list[dict[str, Any]]:
    try:
        baseline = load_baseline(DEFAULT_BASELINE)
    except (OSError, ValueError, json.JSONDecodeError):
        return []
    names = {
        "rand_country": "固定随机国家",
        "rand_bird": "固定随机鸟",
        "b80_letter_count": "b80 字符计数",
    }
    rows = []
    for probe_id, name in names.items():
        cells = [
            value for key, value in baseline.get("cells", {}).items()
            if key.startswith(probe_id + "|")
        ]
        quality = [
            value for key, value in baseline.get("cells_quality", {}).items()
            if key.startswith(probe_id + "|")
        ]
        raw_profiles = ((baseline.get("raw_counts") or {}).get(probe_id) or {}).get("profiles") or {}
        trusted_windows = min((
            len(model_value.get("windows") or {})
            for profile_value in raw_profiles.values()
            for model_value in (profile_value.get("models") or {}).values()
        ), default=0)
        rows.append({
            "id": probe_id,
            "name": name,
            "type": "行为指纹",
            "description": "按固定题面形成类别分布，并与三模型多时间窗可信基线比较。",
            "trusted_profiles": len(cells),
            "between_model_jsd": [cell.get("between_model_jsd") for cell in cells],
            "within_model_jsd": [cell.get("within_model_jsd") for cell in cells],
            "weights": [cell.get("weight") for cell in cells],
            "minimum_valid_rate": min((value.get("minimum_valid_rate", 0.0) for value in quality), default=0.0),
            "trusted_windows": trusted_windows,
            "time_stability_verified": all(bool(cell.get("time_stability_verified")) for cell in cells),
            "scoring_version": baseline.get("scoring_version"),
        })
    return rows


class AppState:
    def __init__(self, runs_root: Path):
        self.token = secrets.token_urlsafe(32)
        self.runs_root = runs_root
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.detector: dict[str, Any] = {"status": "idle", "updated_at": utc_now()}
        self.generator: dict[str, Any] = {"status": "idle", "updated_at": utc_now()}
        self.detector_session: DetectorSession | None = None
        self.detector_thread: threading.Thread | None = None
        self.detector_store: SQLiteStateStore | None = None
        self.detector_run_dir: Path | None = None
        self.generator_session: ProbeGeneratorSession | None = None
        self.generator_thread: threading.Thread | None = None
        self.generator_store: SQLiteStateStore | None = None
        self.generator_run_dir: Path | None = None
        self.pending_custom_probe: dict[str, Any] | None = None
        self._restore_detector_state()
        self._restore_generator_state()

    def _restore_detector_state(self) -> None:
        candidates: list[tuple[str, Path, str]] = []
        for database in (self.runs_root / "detector").glob("session-*/state.sqlite3"):
            try:
                connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True, timeout=2)
                row = connection.execute(
                    "SELECT session_id,created_at FROM sessions WHERE kind='detector' ORDER BY created_at DESC LIMIT 1"
                ).fetchone()
                connection.close()
            except (OSError, sqlite3.Error):
                continue
            if row:
                candidates.append((str(row[1]), database.parent, str(row[0])))
        if not candidates:
            return
        _created_at, run_dir, session_id = max(candidates, key=lambda item: item[0])
        store = SQLiteStateStore(run_dir / "state.sqlite3")
        session = store.session(session_id)
        if session is None:
            store.close()
            return
        if session["status"] in {"running", "stopping"}:
            store.update_session_status(session_id, "interrupted")
            session = store.session(session_id) or session
        self.detector_store = store
        self.detector_run_dir = run_dir
        self.detector = self._status_from_store(store, session_id)

    @staticmethod
    def _status_from_store(store: SQLiteStateStore, session_id: str) -> dict[str, Any]:
        session = store.session(session_id) or {}
        config = session.get("config") or {}
        report = store.report(session_id)
        return {
            "status": session.get("status", "idle"),
            "session_id": session_id,
            "updated_at": session.get("updated_at") or utc_now(),
            "mode": config.get("mode"),
            "preset": config.get("preset"),
            "official": session.get("official"),
            "config_hash": session.get("config_hash"),
            "resume_config": config,
            "claimed_model": session.get("claimed_model"),
            "safe_endpoint": session.get("safe_endpoint"),
            "report_available": report is not None,
            "verdict": report.get("overall_verdict") if report else None,
        }

    def current_detector_store(self) -> SQLiteStateStore | None:
        if self.detector_session is not None:
            return self.detector_session.store
        return self.detector_store

    def _restore_generator_state(self) -> None:
        candidates: list[tuple[str, Path, str]] = []
        for database in (self.runs_root / "generator").glob("session-*/state.sqlite3"):
            try:
                connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True, timeout=2)
                row = connection.execute(
                    "SELECT session_id,created_at FROM sessions WHERE kind='generator' ORDER BY created_at DESC LIMIT 1"
                ).fetchone()
                connection.close()
            except (OSError, sqlite3.Error):
                continue
            if row:
                candidates.append((str(row[1]), database.parent, str(row[0])))
        if not candidates:
            return
        _created_at, run_dir, session_id = max(candidates, key=lambda item: item[0])
        store = SQLiteStateStore(run_dir / "state.sqlite3")
        session = store.session(session_id)
        if session is None:
            store.close()
            return
        if session["status"] in {"running", "stopping"}:
            store.update_session_status(session_id, "interrupted")
        self.generator_store = store
        self.generator_run_dir = run_dir
        self.generator = self._generator_status_from_store(store, session_id, run_dir)

    @staticmethod
    def _generator_status_from_store(store: SQLiteStateStore, session_id: str, run_dir: Path) -> dict[str, Any]:
        session = store.session(session_id) or {}
        config = session.get("config") or {}
        output = run_dir / f"{config.get('probe_id', 'probe')}.gpt56probe.json"
        status = {
            "status": session.get("status", "idle"),
            "session_id": session_id,
            "updated_at": session.get("updated_at") or utc_now(),
            "probe_id": config.get("probe_id"),
            "resume_plan": config,
            "safe_endpoint": session.get("safe_endpoint"),
            "output": str(output) if output.is_file() else None,
        }
        status["progress"] = store.progress(session_id)
        status["progress"]["remaining"] = max(0, status["progress"]["planned"] - status["progress"]["logical_completed"])
        errors = [row for row in store.events(session_id) if row.get("event") == "generator_error"]
        if errors:
            status["error"] = (errors[-1].get("payload") or {}).get("safe_message")
        return status

    def current_generator_store(self) -> SQLiteStateStore | None:
        if self.generator_session is not None:
            return self.generator_session.store
        return self.generator_store

    def safe_status(self, name: str) -> dict[str, Any]:
        with self.lock:
            status = dict(self.detector if name == "detector" else self.generator)
            session = self.detector_session if name == "detector" else self.generator_session
            store = self.current_detector_store() if name == "detector" else self.current_generator_store()
            session_id = status.get("session_id")
        if store is not None and session_id:
            try:
                status = self._status_from_store(store, str(session_id)) if name == "detector" else self._generator_status_from_store(
                    store, str(session_id), self.generator_run_dir or self.runs_root / "generator" / f"session-{session_id}"
                )
            except (KeyError, RuntimeError, sqlite3.Error):
                pass
        if session is not None:
            try:
                status["progress"] = session.progress_snapshot()
            except (KeyError, RuntimeError):
                pass
        return status


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _safe_endpoint(value: str) -> str:
    parsed = urlsplit(normalize_api_base_url(value))
    host = parsed.hostname or ""
    if parsed.port:
        host += f":{parsed.port}"
    return f"{parsed.scheme}://{host}{parsed.path.rstrip('/')}"


def _safe_exception_message(exc: BaseException) -> str:
    safe_message = getattr(exc, "safe_message", None)
    if isinstance(safe_message, str) and safe_message.strip():
        return safe_message.strip()
    message = str(exc).strip() or type(exc).__name__
    message = re.sub(r"(?i)\bBearer\s+\S+", "Bearer <redacted>", message)
    message = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "<redacted-key>", message)
    message = re.sub(r"(?i)[A-Za-z]:\\Users\\[^\\\s]+", lambda _match: r"C:\Users\<redacted>", message)
    message = re.sub(r"\s+", " ", message)[:600]
    translations = (
        (r"detector is already running or stopping", "检测正在运行或停止中，请等待当前会话结束"),
        (r"generator is already running or stopping", "探针生成器正在运行或停止中，请等待当前会话结束"),
        (r"request body too large", "提交的数据过大"),
        (r"JSON body must be an object", "请求正文必须是JSON对象"),
        (r"probe content hash mismatch", "自定义探针内容校验失败，请重新导出后再导入"),
        (r"unsupported fingerprint baseline schema", "指纹基线版本不受支持"),
        (r"fingerprint baseline content hash mismatch", "指纹基线完整性校验失败"),
        (r"runtime catalog is missing", "运行资源缺失，请重新下载完整发行包"),
        (r"No such file|cannot find|not found", "检测所需文件缺失，请重新下载完整发行包"),
    )
    for pattern, translated in translations:
        if re.search(pattern, message, flags=re.IGNORECASE):
            return translated
    if re.search(r"[A-Za-z]{3,}", message):
        return "本地运行发生未分类异常；请下载完整JSON报告并检查安装文件是否完整"
    return message


class Handler(BaseHTTPRequestHandler):
    server: "AppServer"

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _send_json(self, value: Any, status: int = 200) -> None:
        body = _json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_000_000:
            raise ValueError("提交的数据过大")
        value = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
        if not isinstance(value, dict):
            raise ValueError("请求正文必须是JSON对象")
        return value

    def _require_token(self) -> bool:
        if self.headers.get("X-GPT56-Session") != self.server.state.token:
            self._send_json({"error": "本地会话令牌无效，请刷新页面"}, 403)
            return False
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).hostname not in {"127.0.0.1", "localhost"}:
            self._send_json({"error": "已拒绝跨站请求"}, 403)
            return False
        return True

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._send_json({"status": "ok", "binding": "127.0.0.1", "state_transport": "polling"})
            return
        if path in {"/api/bootstrap", "/api/presets"}:
            catalog = preset_catalog()
            self._send_json({
                "session_token": self.server.state.token,
                **catalog,
                "pending_custom_probe": self.server.state.pending_custom_probe,
                "probe_catalog": [
                    {"id": "juice_high", "name": "Juice high", "type": "Juice", "description": "逐条先匹配申报型号，再匹配其他已知型号；共享值优先算申报型号成功。"},
                    {"id": "output_integrity", "name": "32/48 输出完整性", "type": "防改写", "description": "精确返回 32/48 为通过；只有被改成 40 或 40 开头纯数字时才硬报警，其他输出只记无效证据。"},
                    {"id": "juice_coverage", "name": "显式 N 覆盖", "type": "防覆盖", "description": "仅针对把 Sol high 伪装成 40/40xxx 的 Juice 隐藏覆盖：显式定义 N 后检查是否仍被改回已知指纹。"},
                ] + _probability_probe_catalog(),
            })
            return
        if path == "/api/detector/status":
            self._send_json(self.server.state.safe_status("detector"))
            return
        if path == "/api/generator/status":
            self._send_json(self.server.state.safe_status("generator"))
            return
        if path == "/api/detector/report":
            store = self.server.state.current_detector_store()
            status = self.server.state.safe_status("detector")
            session_id = status.get("session_id")
            if store is None or not session_id:
                self._send_json({"error": "当前没有可读取的检测报告"}, 404)
                return
            report = store.report(str(session_id))
            self._send_json(report if report is not None else {"error": "当前检测报告尚未生成"}, 200 if report is not None else 404)
            return
        if path == "/api/generator/export":
            output = self.server.state.generator.get("output")
            if not output:
                self._send_json({"error": "当前没有可下载的探针文件"}, 404)
                return
            file_path = Path(output).resolve()
            root = self.server.state.runs_root.resolve()
            if not file_path.is_file() or not file_path.is_relative_to(root):
                self._send_json({"error": "导出文件路径不在允许的本地运行目录内"}, 403)
                return
            body = file_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="{file_path.name}"')
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        self._serve_static(path)

    def _serve_static(self, path: str) -> None:
        mapping = {"/": "index.html", "/generator": "generator.html"}
        name = mapping.get(path, path.removeprefix("/assets/")) if path.startswith("/assets/") or path in mapping else None
        if not name or ".." in name:
            self.send_error(404)
            return
        file_path = WEB_ROOT / name
        if not file_path.exists():
            self.send_error(404)
            return
        body = file_path.read_bytes()
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type + ("; charset=utf-8" if content_type.startswith(("text/", "application/javascript")) else ""))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if not self._require_token():
            return
        path = urlsplit(self.path).path
        try:
            body = self._body()
            if path == "/api/detector/estimate":
                config = normalize_config(body["config"])
                self._send_json(estimate_single_requests(config) if config["mode"] == "single" else {
                    "continuous": True,
                    "profiles": len(config["request_formats"]) * len(config["context_modes"]),
                    "official": config["official"],
                    "config_hash": config["config_hash"],
                })
            elif path == "/api/detector/start":
                self._start_detector(body)
            elif path == "/api/detector/stop":
                self._stop_detector()
            elif path == "/api/generator/start":
                self._start_generator(body)
            elif path == "/api/generator/stop":
                self._stop_generator()
            elif path == "/api/generator/analyze":
                self._analyze_generator(body)
            elif path == "/api/probe/verify":
                probe = probe_document(body if "probe_file_json" in body else body["probe"])
                verify_probe_file(probe)
                self._send_json({"valid": True, "probe_id": probe["probe_identity"]["probe_id"]})
            elif path == "/api/probe/use-generated":
                self._use_generated_probe()
            else:
                self._send_json({"error": "接口不存在"}, 404)
        except RetentionWriteError as exc:
            self._send_json({"error": _safe_exception_message(exc), "error_type": "retention_path_not_writable"}, 400)
        except (KeyError, TypeError, ValueError) as exc:
            self._send_json({"error": _safe_exception_message(exc)}, 400)
        except Exception as exc:
            self._send_json({"error": _safe_exception_message(exc)}, 500)

    def _start_detector(self, body: dict[str, Any]) -> None:
        base_url = normalize_api_base_url(str(body["base_url"]))
        config = normalize_config(body["config"])
        for custom_probe in config.get("custom_probes", []):
            verify_probe_file(probe_document(custom_probe))
        with self.server.state.lock:
            current = self.server.state.safe_status("detector")
            if current.get("status") in {"running", "stopping"}:
                raise ValueError("detector is already running or stopping")
            resume_session_id = str(body.get("resume_session_id") or "")
            if not resume_session_id and current.get("status") == "interrupted":
                resume_session_id = str(current.get("session_id") or "")
            run_dir: Path
            if resume_session_id:
                store = self.server.state.current_detector_store()
                persisted = store.session(resume_session_id) if store is not None else None
                if persisted is None or persisted.get("status") != "interrupted":
                    raise ValueError("requested detector session is not resumable")
                if persisted.get("config_hash") != config["config_hash"]:
                    raise ValueError("resume config does not match the frozen session")
                if persisted.get("claimed_model") != body.get("model", "gpt-5.6-sol"):
                    raise ValueError("resume model does not match the frozen session")
                if persisted.get("safe_endpoint") != _safe_endpoint(base_url):
                    raise ValueError("resume endpoint does not match the frozen session")
                session_id = resume_session_id
                run_dir = self.server.state.detector_run_dir or self.server.state.runs_root / "detector" / f"session-{session_id}"
            else:
                session_id = secrets.token_hex(8)
                run_dir = self.server.state.runs_root / "detector" / f"session-{session_id}"
            old_session = self.server.state.detector_session
            old_store = self.server.state.detector_store
            if old_session is not None:
                old_session.close()
            elif old_store is not None:
                old_store.close()
            self.server.state.detector_session = None
            self.server.state.detector_store = None
            config["session_id"] = session_id
            session = DetectorSession(
                base_url=base_url,
                model=body.get("model", "gpt-5.6-sol"),
                api_key=body["api_key"],
                config=config,
                directory=run_dir,
                retention_enabled=bool(body.get("retention_enabled")),
                retention_directory=body.get("retention_directory"),
            )
            self.server.state.detector_session = session
            self.server.state.detector_run_dir = run_dir
            self.server.state.detector = {
                "status": "running",
                "session_id": session_id,
                "updated_at": utc_now(),
                "mode": config["mode"],
                "preset": config["preset"],
                "official": config["official"],
                "config_hash": config["config_hash"],
            }

        def target() -> None:
            try:
                report = session.run_single() if config["mode"] == "single" else session.run_continuous()
                final_status = "stopped" if report.get("run_stopped") else "complete"
                status = {
                    "status": final_status,
                    "session_id": session_id,
                    "updated_at": utc_now(),
                    "verdict": report["overall_verdict"],
                    "report_available": True,
                }
            except Exception as exc:
                try:
                    session.store.update_session_status(session_id, "error")
                except RuntimeError:
                    pass
                status = {
                    "status": "error",
                    "session_id": session_id,
                    "updated_at": utc_now(),
                    "error": _safe_exception_message(exc),
                }
            finally:
                session.api_key = ""
                session.transport.api_key = ""
            with self.server.state.lock:
                if self.server.state.detector_session is session and self.server.state.detector.get("session_id") == session_id:
                    self.server.state.detector = self.server.state._status_from_store(session.store, session_id)

        worker = threading.Thread(target=target, daemon=True, name=f"detector-{session_id}")
        with self.server.state.lock:
            self.server.state.detector_thread = worker
        worker.start()
        self._send_json({"started": True, "session_id": session_id, "official": config["official"], "config_hash": config["config_hash"]})

    def _stop_detector(self) -> None:
        result = {
            "accepted": False,
            "stopping": False,
            "session_id": None,
            "previous_status": "idle",
            "current_status": "idle",
            "stop_requested_at": None,
            "active_requests_cancelled": 0,
        }
        with self.server.state.lock:
            session = self.server.state.detector_session
            if session is not None and self.server.state.detector.get("status") == "running":
                result = session.stop()
                result["stopping"] = True
                self.server.state.detector = {**self.server.state.detector, "status": "stopping", "updated_at": utc_now()}
            elif session is not None:
                result.update({
                    "session_id": session.session_id,
                    "previous_status": self.server.state.detector.get("status", "unknown"),
                    "current_status": self.server.state.detector.get("status", "unknown"),
                })
        self._send_json(result)

    def _start_generator(self, body: dict[str, Any]) -> None:
        base_url = normalize_api_base_url(str(body["base_url"]))
        with self.server.state.lock:
            if self.server.state.generator.get("status") in {"running", "stopping"}:
                raise ValueError("generator is already running or stopping")
            if self.server.state.generator_session is not None:
                self.server.state.generator_session.close()
                self.server.state.generator_session = None
            value = dict(body["plan"])
            for key in ("request_formats", "context_modes", "tags"):
                if key in value:
                    value[key] = tuple(value[key])
            plan = GeneratorPlan(**value)
            plan.validate()
            resume_session_id = str(body.get("resume_session_id") or "")
            current = self.server.state.safe_status("generator")
            if not resume_session_id and current.get("status") == "interrupted":
                resume_session_id = str(current.get("session_id") or "")
            if resume_session_id:
                store = self.server.state.current_generator_store()
                persisted = store.session(resume_session_id) if store is not None else None
                if persisted is None or persisted.get("status") != "interrupted":
                    raise ValueError("requested generator session is not resumable")
                plan_hash = hashlib.sha256(canonical_json(plan.to_public_dict()).encode("utf-8")).hexdigest()
                if persisted.get("config_hash") != plan_hash:
                    raise ValueError("resume plan does not match the frozen generator session")
                if persisted.get("safe_endpoint") and persisted.get("safe_endpoint") != _safe_endpoint(base_url):
                    raise ValueError("resume endpoint does not match the frozen generator session")
                session_id = resume_session_id
                run_dir = self.server.state.generator_run_dir or self.server.state.runs_root / "generator" / f"session-{session_id}"
            else:
                session_id = secrets.token_hex(8)
                run_dir = self.server.state.runs_root / "generator" / f"session-{session_id}"
            detached = self.server.state.generator_store
            if detached is not None:
                detached.close()
            self.server.state.generator_store = None
            session = ProbeGeneratorSession(
                plan, run_dir, session_id=session_id, safe_endpoint=_safe_endpoint(base_url),
            )
            self.server.state.generator_session = session
            self.server.state.generator_run_dir = run_dir
            self.server.state.generator = {"status": "running", "session_id": session_id, "updated_at": utc_now(), "probe_id": plan.probe_id}
        api_key = str(body["api_key"])
        local = threading.local()
        transports: list[StreamingTransport] = []
        transport_lock = threading.Lock()

        def request(job: dict[str, Any], messages: list[dict[str, str]]) -> dict[str, Any]:
            if not hasattr(local, "transport"):
                local.transport = StreamingTransport(
                    base_url,
                    api_key,
                    timeout=300 if job["context_mode"] == "fixed_32k_history" or job["request_format"] == "native_codex" else 180,
                    cancellation=session.cancellation,
                )
                with transport_lock:
                    transports.append(local.transport)
            result = local.transport.post(
                model=job["upstream_model"],
                messages=messages,
                effort=job["effort"],
                request_format=job["request_format"],
                context_mode=job["context_mode"],
                cache_key=job["job_id"],
                job_id=job["job_id"],
                session_id=session_id,
            )
            return {"answer": result.answer, "streaming": True, "http_status": result.meta.get("http_status"), "usage": result.response.get("usage")}

        def target() -> None:
            nonlocal api_key
            try:
                progress = session.run(request)
                final_status = str(progress.pop("status", "error"))
                error = progress.pop("error", None)
                status = {"status": final_status, "session_id": session_id, "updated_at": utc_now(), **progress}
                if error:
                    status["error"] = error
            except Exception as exc:
                status = {"status": "error", "session_id": session_id, "updated_at": utc_now(), "error": _safe_exception_message(exc)}
            finally:
                api_key = ""
                with transport_lock:
                    for transport in transports:
                        transport.api_key = ""
                    transports.clear()
            with self.server.state.lock:
                if self.server.state.generator_session is session and self.server.state.generator.get("session_id") == session_id:
                    self.server.state.generator = status

        worker = threading.Thread(target=target, daemon=True, name=f"generator-{session_id}")
        with self.server.state.lock:
            self.server.state.generator_thread = worker
        worker.start()
        self._send_json({"started": True, "session_id": session_id})

    def _stop_generator(self) -> None:
        result = {
            "accepted": False,
            "stopping": False,
            "session_id": None,
            "previous_status": "idle",
            "current_status": "idle",
            "stop_requested_at": None,
            "active_requests_cancelled": 0,
        }
        with self.server.state.lock:
            session = self.server.state.generator_session
            current_status = self.server.state.generator.get("status", "idle")
            if session is not None and current_status == "running":
                result = session.stop()
                result["stopping"] = True
                self.server.state.generator = {
                    **self.server.state.generator,
                    "status": "stopping",
                    "updated_at": utc_now(),
                }
            elif session is not None:
                result.update({
                    "session_id": session.session_id,
                    "previous_status": current_status,
                    "current_status": current_status,
                })
        self._send_json(result)

    def _analyze_generator(self, body: dict[str, Any]) -> None:
        session = self.server.state.generator_session
        if session is None:
            store = self.server.state.current_generator_store()
            status = self.server.state.safe_status("generator")
            session_id = str(status.get("session_id") or "")
            persisted = store.session(session_id) if store is not None and session_id else None
            if persisted is None or persisted.get("status") not in {"collected", "complete"}:
                raise ValueError("generator session unavailable")
            plan_value = dict(persisted["config"])
            for key in ("request_formats", "context_modes", "tags"):
                if key in plan_value:
                    plan_value[key] = tuple(plan_value[key])
            plan = GeneratorPlan(**plan_value)
            if store is not None:
                store.close()
            self.server.state.generator_store = None
            session = ProbeGeneratorSession(
                plan,
                self.server.state.generator_run_dir or self.server.state.runs_root / "generator" / f"session-{session_id}",
                session_id=session_id,
                safe_endpoint=persisted.get("safe_endpoint"),
                activate=False,
            )
            self.server.state.generator_session = session
        output = Path(body.get("output") or session.directory / f"{session.plan.probe_id}.gpt56probe.json")
        export = session.analyze_and_export(output)
        session.store.update_session_status(session.session_id, "complete")
        with self.server.state.lock:
            if self.server.state.generator_session is session:
                self.server.state.generator = {
                    **self.server.state.generator,
                    "status": "complete",
                    "updated_at": utc_now(),
                    "output": str(output),
                    "analysis": {"formal_eligible": export["formal_eligible"]},
                }
        self._send_json({"complete": True, "output": str(output), "probe": export})

    def _use_generated_probe(self) -> None:
        output = self.server.state.generator.get("output")
        if not output:
            raise ValueError("当前没有可导出的探针结果")
        file_path = Path(output).resolve()
        root = self.server.state.runs_root.resolve()
        if not file_path.is_file() or not file_path.is_relative_to(root):
            raise ValueError("generator export path rejected")
        probe = json.loads(file_path.read_text(encoding="utf-8"))
        verify_probe_file(probe)
        with self.server.state.lock:
            self.server.state.pending_custom_probe = wrap_probe_file(probe)
        self._send_json({"ready": True, "probe_id": probe["probe_identity"]["probe_id"]})


class AppServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], state: AppState):
        super().__init__(address, Handler)
        self.state = state

    def server_close(self) -> None:
        with self.state.lock:
            detector = self.state.detector_session
            detector_thread = self.state.detector_thread
            detached_detector_store = self.state.detector_store
            generator = self.state.generator_session
            generator_thread = self.state.generator_thread
            detached_generator_store = self.state.generator_store
        for session in (detector, generator):
            if session is not None:
                try:
                    session.stop()
                except RuntimeError:
                    pass
        for worker in (detector_thread, generator_thread):
            if worker is not None and worker is not threading.current_thread():
                worker.join(timeout=15)
        for session in (detector, generator):
            if session is not None:
                try:
                    session.close()
                except RuntimeError:
                    pass
        if detached_detector_store is not None:
            try:
                detached_detector_store.close()
            except RuntimeError:
                pass
        if detached_generator_store is not None:
            try:
                detached_generator_store.close()
            except RuntimeError:
                pass
        super().server_close()


def create_server(*, port: int = 0, runs_root: str | Path | None = None) -> AppServer:
    state = AppState(Path(runs_root or Path.cwd() / "gpt56_vnext_runs"))
    return AppServer(("127.0.0.1", port), state)


__all__ = ["AppServer", "AppState", "create_server"]
