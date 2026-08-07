#!/usr/bin/env python3
"""Simple desktop interface for the GPT-5.6 detector and monitor."""

from __future__ import annotations

from datetime import datetime
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import webbrowser

from gpt56_report_html import write_report_html


APP_DIR = Path(__file__).resolve().parent
EFFORT_LABELS = {
    "low": "低档",
    "medium": "中档",
    "high": "高档",
    "xhigh": "超高档",
    "max": "最高档",
}


class DetectorGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("GPT-5.6 API 检测器 v3.1.1")
        self.root.geometry("1180x800")
        self.root.minsize(940, 660)
        self.process: subprocess.Popen[str] | None = None
        self.output_queue: queue.Queue[str | None] = queue.Queue()
        self.report_path: Path | None = None
        self.last_report_mtime = 0.0

        self.mode = tk.StringVar(value="juice_only")
        self.run_kind = tk.StringVar(value="continuous")
        self.trusted_url = tk.StringVar()
        self.trusted_model = tk.StringVar(value="gpt-5.6-sol")
        self.trusted_key = tk.StringVar()
        self.candidate_url = tk.StringVar()
        self.candidate_model = tk.StringVar(value="gpt-5.6-sol")
        self.candidate_key = tk.StringVar()
        self.same_key = tk.BooleanVar(value=False)
        self.include_request_id = tk.BooleanVar(value=True)
        self.include_timestamps = tk.BooleanVar(value=True)
        self.include_duration = tk.BooleanVar(value=True)
        self.include_http_status = tk.BooleanVar(value=True)
        self.include_token_usage = tk.BooleanVar(value=True)
        self.include_response_size = tk.BooleanVar(value=True)
        self.include_server_ip = tk.BooleanVar(value=False)
        self.include_client_ip = tk.BooleanVar(value=False)
        self.estimate_tokens = tk.BooleanVar(value=False)
        self.client_ip_lookup_url = tk.StringVar(
            value="https://api64.ipify.org?format=json"
        )
        self.min_interval = tk.StringVar(value="150")
        self.max_interval = tk.StringVar(value="210")
        self.single_workers = tk.StringVar(value="8")
        self.output_file = tk.StringVar()
        self.status_text = tk.StringVar(value="尚未启动")
        self.verdict_text = tk.StringVar(value="等待检测")
        self.verdict_detail = tk.StringVar(value="填写左侧设置后开始。")
        self.health_text = tk.StringVar(value="-")
        self.network_text = tk.StringVar(value="-")
        self.model_text = tk.StringVar(value="-")
        self.output_control_text = tk.StringVar(value="-")

        self.root.option_add("*Font", "{Segoe UI} 12")
        self._configure_style()
        self._build_ui()
        self._set_default_report()
        self._mode_changed()
        self._run_kind_changed()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(200, self._poll_output)
        self.root.after(700, self._poll_report)

    def _configure_style(self) -> None:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("App.TFrame", background="#f3f5f7")
        style.configure("Side.TFrame", background="#ffffff")
        for widget_style in (
            "TLabel",
            "TButton",
            "TEntry",
            "TRadiobutton",
            "TCheckbutton",
            "TLabelframe.Label",
            "TSpinbox",
        ):
            style.configure(widget_style, font=("Segoe UI", 12))
        style.configure("Header.TLabel", background="#17242d", foreground="#ffffff", font=("Segoe UI", 20, "bold"))
        style.configure("HeaderSub.TLabel", background="#17242d", foreground="#c9d3da", font=("Segoe UI", 12))
        style.configure("Section.TLabel", background="#ffffff", foreground="#1d2935", font=("Segoe UI", 13, "bold"))
        style.configure("Verdict.TLabel", font=("Segoe UI", 22, "bold"))
        style.configure("Detail.TLabel", foreground="#53606d", font=("Segoe UI", 12))
        style.configure("MetricTitle.TLabel", foreground="#66717e", font=("Segoe UI", 11))
        style.configure("MetricValue.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Primary.TButton", font=("Segoe UI", 12, "bold"))
        style.configure("Treeview", rowheight=30, font=("Segoe UI", 11))
        style.configure("Treeview.Heading", font=("Segoe UI", 11, "bold"))
        style.configure("TNotebook.Tab", padding=(12, 7), font=("Segoe UI", 11))

    def _build_ui(self) -> None:
        self.root.configure(background="#f3f5f7")
        header = tk.Frame(self.root, bg="#17242d", height=76)
        header.pack(fill="x")
        header.pack_propagate(False)
        ttk.Label(header, text="GPT-5.6 API 检测器", style="Header.TLabel").pack(anchor="w", padx=24, pady=(14, 0))
        ttk.Label(header, text="加密状态能力、Juice 型号与输出完整性", style="HeaderSub.TLabel").pack(anchor="w", padx=24)

        body = ttk.Frame(self.root, style="App.TFrame")
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=1)

        side_shell = tk.Frame(body, bg="#ffffff", width=365)
        side_shell.grid(row=0, column=0, sticky="nsew")
        side_shell.grid_propagate(False)
        side_canvas = tk.Canvas(
            side_shell,
            bg="#ffffff",
            width=345,
            highlightthickness=0,
            borderwidth=0,
        )
        self.side_canvas = side_canvas
        side_scroll = ttk.Scrollbar(
            side_shell, orient="vertical", command=side_canvas.yview
        )
        side_canvas.configure(yscrollcommand=side_scroll.set)
        side_canvas.pack(side="left", fill="both", expand=True)
        side_scroll.pack(side="right", fill="y")
        side = ttk.Frame(side_canvas, style="Side.TFrame", padding=18)
        side_window = side_canvas.create_window((0, 0), window=side, anchor="nw")
        side.bind(
            "<Configure>",
            lambda _event: side_canvas.configure(
                scrollregion=side_canvas.bbox("all")
            ),
        )
        side_canvas.bind(
            "<Configure>",
            lambda event: side_canvas.itemconfigure(
                side_window, width=event.width
            ),
        )
        content = ttk.Frame(body, style="App.TFrame", padding=16)
        content.grid(row=0, column=1, sticky="nsew")
        content.columnconfigure(0, weight=1)
        content.rowconfigure(0, weight=1)

        self._build_settings(side)
        self._bind_sidebar_mousewheel(side_canvas, side)
        self._build_content(content)

    def _bind_sidebar_mousewheel(
        self,
        canvas: tk.Canvas,
        widget: tk.Misc,
    ) -> None:
        def scroll(event: tk.Event) -> str:
            if getattr(event, "num", None) == 4:
                direction = -1
            elif getattr(event, "num", None) == 5:
                direction = 1
            else:
                delta = int(getattr(event, "delta", 0))
                direction = -1 if delta > 0 else 1
            canvas.yview_scroll(direction * 3, "units")
            return "break"

        def bind_tree(current: tk.Misc) -> None:
            current.bind("<MouseWheel>", scroll, add="+")
            current.bind("<Button-4>", scroll, add="+")
            current.bind("<Button-5>", scroll, add="+")
            for child in current.winfo_children():
                bind_tree(child)

        bind_tree(canvas)
        bind_tree(widget)

    def _build_settings(self, parent: ttk.Frame) -> None:
        ttk.Label(parent, text="运行方式", style="Section.TLabel").pack(anchor="w")
        modes = ttk.Frame(parent, style="Side.TFrame")
        modes.pack(fill="x", pady=(6, 12))
        modes.columnconfigure((0, 1), weight=1)
        ttk.Radiobutton(modes, text="仅 Juice", value="juice_only", variable=self.mode, command=self._mode_changed).grid(row=0, column=0, sticky="w", padx=(0, 8), pady=2)
        ttk.Radiobutton(modes, text="综合检测", value="combined", variable=self.mode, command=self._mode_changed).grid(row=0, column=1, sticky="w", padx=(0, 8), pady=2)
        ttk.Radiobutton(modes, text="单次", value="single", variable=self.run_kind, command=self._run_kind_changed).grid(row=1, column=0, sticky="w", padx=(0, 8), pady=2)
        ttk.Radiobutton(modes, text="持续监控", value="continuous", variable=self.run_kind, command=self._run_kind_changed).grid(row=1, column=1, sticky="w", padx=(0, 8), pady=2)

        self.trusted_frame = ttk.LabelFrame(parent, text="可信 API", padding=10)
        self.trusted_frame.pack(fill="x", pady=(0, 10))
        self._entry(self.trusted_frame, "地址", self.trusted_url)
        self._entry(self.trusted_frame, "模型", self.trusted_model)
        self._entry(self.trusted_frame, "API key", self.trusted_key, secret=True)

        candidate = ttk.LabelFrame(parent, text="待测 API", padding=10)
        candidate.pack(fill="x", pady=(0, 10))
        self._entry(candidate, "地址", self.candidate_url)
        self._entry(candidate, "模型", self.candidate_model)
        self.candidate_key_entry = self._entry(candidate, "API key", self.candidate_key, secret=True)
        self.same_key_check = ttk.Checkbutton(candidate, text="与可信 API 使用相同 key", variable=self.same_key, command=self._same_key_changed)
        self.same_key_check.pack(anchor="w", pady=(5, 0))

        self.interval_frame = ttk.LabelFrame(parent, text="持续监控间隔", padding=10)
        self.interval_frame.pack(fill="x", pady=(0, 10))
        interval_row = ttk.Frame(self.interval_frame)
        interval_row.pack(fill="x")
        ttk.Label(interval_row, text="最短秒数").grid(row=0, column=0, sticky="w")
        ttk.Label(interval_row, text="最长秒数").grid(row=0, column=1, sticky="w", padx=(10, 0))
        ttk.Entry(interval_row, textvariable=self.min_interval, width=12).grid(row=1, column=0, sticky="ew")
        ttk.Entry(interval_row, textvariable=self.max_interval, width=12).grid(row=1, column=1, sticky="ew", padx=(10, 0))
        interval_row.columnconfigure((0, 1), weight=1)

        self.workers_frame = ttk.LabelFrame(parent, text="单次检测并发", padding=10)
        self.workers_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(self.workers_frame, text="并发请求数（推荐 8）").pack(anchor="w")
        self.workers_spinbox = ttk.Spinbox(
            self.workers_frame,
            from_=1,
            to=16,
            textvariable=self.single_workers,
            width=8,
        )
        self.workers_spinbox.pack(anchor="w", pady=(4, 0))

        metadata = ttk.LabelFrame(parent, text="报告包含信息", padding=10)
        metadata.pack(fill="x", pady=(0, 10))
        ttk.Label(
            metadata,
            text="默认字段可用于精确定位每次请求；IP 默认关闭。",
            style="Detail.TLabel",
            wraplength=315,
        ).pack(anchor="w", pady=(0, 5))
        default_fields = (
            ("Request ID（客户端关联 ID + 服务端 ID）", self.include_request_id),
            ("时间", self.include_timestamps),
            ("耗时", self.include_duration),
            ("HTTP 状态", self.include_http_status),
            ("服务端 usage token", self.include_token_usage),
            ("响应大小", self.include_response_size),
        )
        for label, variable in default_fields:
            ttk.Checkbutton(metadata, text=label, variable=variable).pack(anchor="w")
        ttk.Separator(metadata).pack(fill="x", pady=5)
        ttk.Checkbutton(
            metadata,
            text="服务端 IP（目标 DNS 结果；代理时不是代理 peer IP）",
            variable=self.include_server_ip,
        ).pack(anchor="w")
        ttk.Checkbutton(
            metadata,
            text="发起端真实出口 IP（通过代理感知的 IP 查询）",
            variable=self.include_client_ip,
        ).pack(anchor="w")
        self._entry(metadata, "出口 IP 查询地址", self.client_ip_lookup_url)
        ttk.Checkbutton(
            metadata,
            text="高级：无 usage 时估算 token（不一定准确）",
            variable=self.estimate_tokens,
        ).pack(anchor="w")

        output = ttk.LabelFrame(parent, text="报告", padding=10)
        output.pack(fill="x", pady=(0, 12))
        output_row = ttk.Frame(output)
        output_row.pack(fill="x")
        ttk.Entry(output_row, textvariable=self.output_file).pack(side="left", fill="x", expand=True)
        ttk.Button(output_row, text="选择", command=self._browse_report, width=7).pack(side="left", padx=(6, 0))
        ttk.Label(output, text="同时生成 JSON 与同名 HTML", style="Detail.TLabel").pack(anchor="w", pady=(4, 0))

        buttons = ttk.Frame(parent, style="Side.TFrame")
        buttons.pack(fill="x")
        self.start_button = ttk.Button(buttons, text="开始检测", command=self._start, style="Primary.TButton")
        self.start_button.pack(side="left", fill="x", expand=True)
        self.stop_button = ttk.Button(buttons, text="停止", command=self._stop, state="disabled", width=9)
        self.stop_button.pack(side="left", padx=(8, 0))
        self.open_button = ttk.Button(parent, text="打开简明 HTML 报告", command=self._open_report, state="disabled")
        self.open_button.pack(fill="x", pady=(8, 0))
        ttk.Button(parent, text="加载已有 JSON 报告", command=self._load_existing_report).pack(fill="x", pady=(6, 0))
        ttk.Label(parent, textvariable=self.status_text, style="Detail.TLabel", wraplength=325).pack(anchor="w", pady=(10, 0))

    def _entry(self, parent: ttk.Frame, label: str, variable: tk.StringVar, secret: bool = False) -> ttk.Entry:
        ttk.Label(parent, text=label).pack(anchor="w", pady=(0, 2))
        entry = ttk.Entry(parent, textvariable=variable, show="*" if secret else "")
        entry.pack(fill="x", pady=(0, 6))
        return entry

    def _build_content(self, parent: ttk.Frame) -> None:
        notebook = ttk.Notebook(parent)
        notebook.grid(row=0, column=0, sticky="nsew")
        status_tab = ttk.Frame(notebook, padding=18)
        report_tab = ttk.Frame(notebook, padding=18)
        log_tab = ttk.Frame(notebook, padding=10)
        notebook.add(status_tab, text="实时状态")
        notebook.add(report_tab, text="简明报告")
        notebook.add(log_tab, text="运行日志")
        self._build_status_tab(status_tab)
        self._build_report_tab(report_tab)
        self.log = tk.Text(log_tab, wrap="word", font=("Consolas", 11), bg="#101820", fg="#e7edf2", insertbackground="#ffffff", relief="flat")
        self.log.pack(fill="both", expand=True)
        self.log.configure(state="disabled")

    def _build_status_tab(self, tab: ttk.Frame) -> None:
        tab.columnconfigure(0, weight=1)
        ttk.Label(tab, textvariable=self.verdict_text, style="Verdict.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(tab, textvariable=self.verdict_detail, style="Detail.TLabel", wraplength=650).grid(row=1, column=0, sticky="w", pady=(4, 18))
        metrics = ttk.Frame(tab)
        metrics.grid(row=2, column=0, sticky="ew")
        metrics.columnconfigure((0, 1, 2), weight=1)
        self._metric(metrics, 0, "监控健康度", self.health_text)
        self._metric(metrics, 1, "线路质量", self.network_text)
        self._metric(metrics, 2, "具体型号", self.model_text)
        ttk.Separator(tab).grid(row=3, column=0, sticky="ew", pady=18)
        self.strong_progress_label = ttk.Label(tab, text="强检测窗口")
        self.strong_progress_label.grid(row=4, column=0, sticky="w")
        self.strong_progress = ttk.Progressbar(tab, maximum=20)
        self.strong_progress.grid(row=5, column=0, sticky="ew", pady=(4, 14))
        self.juice_progress_label = ttk.Label(tab, text="Juice 高档窗口")
        self.juice_progress_label.grid(row=6, column=0, sticky="w")
        self.juice_progress = ttk.Progressbar(tab, maximum=20)
        self.juice_progress.grid(row=7, column=0, sticky="ew", pady=(4, 14))
        ttk.Label(tab, text="高档字面量输出完整性").grid(row=8, column=0, sticky="w")
        ttk.Label(tab, textvariable=self.output_control_text, style="Detail.TLabel", wraplength=650).grid(row=9, column=0, sticky="w", pady=(4, 0))

    def _metric(self, parent: ttk.Frame, column: int, title: str, variable: tk.StringVar) -> None:
        frame = ttk.Frame(parent, padding=(0, 8))
        frame.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 8, 0))
        ttk.Label(frame, text=title, style="MetricTitle.TLabel").pack(anchor="w")
        ttk.Label(frame, textvariable=variable, style="MetricValue.TLabel", wraplength=180).pack(anchor="w")

    def _build_report_tab(self, tab: ttk.Frame) -> None:
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        self.alerts = tk.Text(tab, height=5, wrap="word", bg="#fff6e5", fg="#7a4d00", relief="flat", padx=10, pady=8)
        self.alerts.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        self.alerts.insert("1.0", "报告生成后，这里会显示需要关注的异常。")
        self.alerts.configure(state="disabled")
        columns = ("effort", "passed", "numeric", "window")
        self.effort_table = ttk.Treeview(tab, columns=columns, show="headings", height=6)
        for key, text, width in (("effort", "档位", 110), ("passed", "通过", 90), ("numeric", "有效数字", 100), ("window", "滚动窗口", 120)):
            self.effort_table.heading(key, text=text)
            self.effort_table.column(key, width=width, anchor="center")
        self.effort_table.grid(row=1, column=0, sticky="nsew")

    def _mode_changed(self) -> None:
        combined = self.mode.get() == "combined"
        state = "normal" if combined else "disabled"
        for child in self.trusted_frame.winfo_children():
            try:
                child.configure(state=state)
            except tk.TclError:
                pass
        self.same_key_check.configure(state=state)
        if not combined:
            self.same_key.set(False)
            self.candidate_key_entry.configure(state="normal")

    def _run_kind_changed(self) -> None:
        continuous = self.run_kind.get() == "continuous"
        state = "normal" if continuous else "disabled"
        for child in self.interval_frame.winfo_children():
            for item in child.winfo_children() if child.winfo_children() else (child,):
                try:
                    item.configure(state=state)
                except tk.TclError:
                    pass
        self.workers_spinbox.configure(state="disabled" if continuous else "normal")
        if continuous:
            self.strong_progress_label.configure(text="强检测滚动窗口")
            self.juice_progress_label.configure(text="Juice 高档滚动窗口")
            self.effort_table.heading("window", text="滚动窗口")
        else:
            self.strong_progress_label.configure(text="本次加密状态挑战")
            self.juice_progress_label.configure(text="本次 Juice 高档样本")
            self.effort_table.heading("window", text="本次样本")
        self._set_default_report()

    def _same_key_changed(self) -> None:
        self.candidate_key_entry.configure(state="disabled" if self.same_key.get() else "normal")

    def _set_default_report(self) -> None:
        prefix = "monitor-report" if self.run_kind.get() == "continuous" else "probe-report"
        self.output_file.set(str(APP_DIR / f"{prefix}-{datetime.now():%Y%m%d-%H%M%S}.json"))

    def _browse_report(self) -> None:
        selected = filedialog.asksaveasfilename(initialdir=APP_DIR, defaultextension=".json", filetypes=(("JSON 报告", "*.json"),))
        if selected:
            self.output_file.set(selected)

    def _build_command(self) -> tuple[list[str], dict[str, str], Path]:
        candidate_url = self.candidate_url.get().strip().rstrip("/")
        candidate_key = self.trusted_key.get() if self.same_key.get() else self.candidate_key.get()
        if not candidate_url or not candidate_key:
            raise ValueError("请填写待测 API 地址和 key。")
        output = Path(self.output_file.get().strip()).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        continuous = self.run_kind.get() == "continuous"
        script = APP_DIR / ("gpt56_reasoning_monitor.py" if continuous else "gpt56_reasoning_probe.py")
        gap_min, gap_max = ("2", "5") if continuous else ("0", "0")
        command = [sys.executable, str(script), "--candidate-base-url", candidate_url, "--candidate-model", self.candidate_model.get().strip() or "gpt-5.6-sol", "--candidate-retries", "2", "--candidate-min-gap", gap_min, "--candidate-max-gap", gap_max, "--output", str(output)]
        metadata_flags = (
            ("--omit-request-id", not self.include_request_id.get()),
            ("--omit-timestamps", not self.include_timestamps.get()),
            ("--omit-duration", not self.include_duration.get()),
            ("--omit-http-status", not self.include_http_status.get()),
            ("--omit-token-usage", not self.include_token_usage.get()),
            ("--omit-response-size", not self.include_response_size.get()),
            ("--include-server-ip", self.include_server_ip.get()),
            ("--include-client-ip", self.include_client_ip.get()),
            ("--estimate-tokens", self.estimate_tokens.get()),
        )
        for flag, enabled in metadata_flags:
            if enabled:
                command.append(flag)
        command.extend(["--client-ip-lookup-url", self.client_ip_lookup_url.get().strip()])
        if continuous:
            minimum = int(self.min_interval.get())
            maximum = int(self.max_interval.get())
            if minimum < 1 or maximum < minimum:
                raise ValueError("持续间隔必须满足 1 <= 最短 <= 最长。")
            command.extend(["--min-interval", str(minimum), "--max-interval", str(maximum), "--window", "20", "--required-matches", "15"])
        else:
            workers = int(self.single_workers.get())
            if not 1 <= workers <= 16:
                raise ValueError("单次检测并发数必须在 1–16 之间。")
            command.extend(["--trials", "20", "--min-match-rate", "0.75", "--min-matches", "15", "--juice-repeats", "3", "--workers", str(workers)])
        if self.mode.get() == "juice_only":
            command.append("--juice-only")
        else:
            trusted_url = self.trusted_url.get().strip().rstrip("/")
            trusted_key = self.trusted_key.get()
            if not trusted_url or not trusted_key:
                raise ValueError("综合模式需要可信 API 地址和 key。")
            command.extend(["--trusted-base-url", trusted_url, "--trusted-model", self.trusted_model.get().strip() or "gpt-5.6-sol"])
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        env["CANDIDATE_API_KEY"] = candidate_key
        if self.mode.get() == "combined":
            env["TRUSTED_API_KEY"] = self.trusted_key.get()
        return command, env, output

    def _start(self) -> None:
        if self.process and self.process.poll() is None:
            return
        try:
            command, env, output = self._build_command()
        except (ValueError, OSError) as exc:
            messagebox.showerror("无法开始", str(exc), parent=self.root)
            return
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        try:
            self.process = subprocess.Popen(command, env=env, cwd=APP_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace", bufsize=1, creationflags=flags)
        except OSError as exc:
            messagebox.showerror("无法启动检测器", str(exc), parent=self.root)
            return
        env.pop("TRUSTED_API_KEY", None)
        env.pop("CANDIDATE_API_KEY", None)
        self.report_path = output
        self.last_report_mtime = 0.0
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.open_button.configure(state="disabled")
        self.status_text.set("检测正在运行，key 仅存在于检测子进程环境。")
        self.verdict_text.set("正在收集证据")
        self.verdict_detail.set("首份报告生成后会自动刷新。")
        self._clear_log()
        threading.Thread(target=self._read_output, daemon=True).start()

    def _read_output(self) -> None:
        process = self.process
        if not process or not process.stdout:
            return
        for line in process.stdout:
            self.output_queue.put(line)
        self.output_queue.put(None)

    def _poll_output(self) -> None:
        try:
            while True:
                item = self.output_queue.get_nowait()
                if item is None:
                    code = self.process.poll() if self.process else None
                    self.start_button.configure(state="normal")
                    self.stop_button.configure(state="disabled")
                    self.status_text.set(f"检测进程已结束，退出码 {code}。")
                else:
                    self._append_log(item)
        except queue.Empty:
            pass
        self.root.after(200, self._poll_output)

    def _poll_report(self) -> None:
        path = self.report_path
        if path and path.is_file():
            try:
                mtime = path.stat().st_mtime
                if mtime > self.last_report_mtime:
                    report = json.loads(path.read_text(encoding="utf-8"))
                    self.last_report_mtime = mtime
                    self._render_report(report)
                    if path.with_suffix(".html").is_file():
                        self.open_button.configure(state="normal")
            except (OSError, json.JSONDecodeError) as exc:
                self.status_text.set(f"报告正在更新：{exc}")
        self.root.after(700, self._poll_report)

    def _render_report(self, report: dict) -> None:
        combined = report.get("combined_summary", {})
        health = report.get("monitor_health_summary", {})
        network = report.get("network_summary", {})
        juice = report.get("juice_summary", {})
        control = report.get("output_literal_control_summary") or {}
        rolling = report.get("rolling_summary", report.get("summary", {}))
        single = str(report.get("mode", "")).endswith("_single_v3_1_1")
        self.verdict_text.set(combined.get("title_cn", report.get("combined_verdict", "检测中")))
        self.verdict_detail.set(combined.get("explanation_cn", report.get("reason", "")))
        self.health_text.set("单次结果" if single else health.get("title_cn", health.get("status", "检测中")))
        self.network_text.set(network.get("title_cn", network.get("status", "-")))
        self.model_text.set(juice.get("likely_model_cn", "尚未确定"))
        if single:
            self.strong_progress_label.configure(text="本次加密状态挑战")
            self.juice_progress_label.configure(text="本次 Juice 高档样本")
            summary = report.get("summary", {})
            strong_value = summary.get("valid_trials", summary.get("candidate_attempts", 0))
        else:
            self.strong_progress_label.configure(text="强检测滚动窗口")
            self.juice_progress_label.configure(text="Juice 高档滚动窗口")
            strong_value = rolling.get("candidate_attempts_in_window", rolling.get("candidate_attempts", 0))
        self.strong_progress.configure(value=int(strong_value or 0))
        high = juice.get("effort_stats", {}).get("high", {})
        self.juice_progress.configure(value=int(high.get("observations", 0) or 0))
        exact = control.get("exact_by_expected", {})
        counts = control.get("expected_counts", {})
        self.output_control_text.set(
            f"{control.get('title_cn', '暂无样本')}；48 {exact.get('48', 0)}/{counts.get('48', 0)}，"
            f"32 {exact.get('32', 0)}/{counts.get('32', 0)}，会话异常 {control.get('session_non_exact_successes', 0)}"
        )
        for item in self.effort_table.get_children():
            self.effort_table.delete(item)
        for effort in ("low", "medium", "high", "xhigh", "max"):
            item = juice.get("effort_stats", {}).get(effort, {})
            sample_text = str(item.get("observations", 0)) if single else f"{item.get('observations', 0)} / {item.get('window_limit', 0)}"
            self.effort_table.insert("", "end", values=(EFFORT_LABELS[effort], item.get("pass_count", 0), item.get("numeric_samples", 0), sample_text))
        self.effort_table.heading("window", text="本次样本" if single else "滚动窗口")
        alerts = []
        if combined.get("passed_cn") == "不通过":
            alerts.append(combined.get("title_cn", "检测未通过"))
        if juice.get("status") == "mixed_or_inconsistent":
            alerts.append("检测到互斥 Juice 型号指纹")
        if control.get("status") == "output_rewrite_suspected":
            latest = (control.get("session_anomalies") or [{}])[-1]
            alerts.append(f"字面量输出异常：要求 {latest.get('expected_text')}，得到 {latest.get('observed_text')}")
        if health.get("current_monitoring_effective") is False:
            alerts.append(health.get("title_cn", "监控未刷新"))
        self.alerts.configure(state="normal")
        self.alerts.delete("1.0", "end")
        self.alerts.insert("1.0", "\n".join(f"- {item}" for item in alerts) if alerts else "当前没有检测到需要立即处理的异常。")
        self.alerts.configure(state="disabled")
        self.status_text.set(f"报告已更新：{report.get('updated_at', report.get('created_at', '-'))}")

    def _stop(self) -> None:
        process = self.process
        if not process or process.poll() is not None:
            return
        try:
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.send_signal(signal.SIGINT)
        except (OSError, ValueError):
            process.terminate()
        self.status_text.set("正在停止，最新报告会保留。")

    def _open_report(self) -> None:
        if not self.report_path:
            return
        html_path = self.report_path.with_suffix(".html")
        if html_path.is_file():
            webbrowser.open(html_path.resolve().as_uri())
        else:
            messagebox.showinfo("报告尚未生成", "等待首轮完成后再打开。", parent=self.root)

    def _load_existing_report(self) -> None:
        selected = filedialog.askopenfilename(
            initialdir=APP_DIR,
            filetypes=(("JSON 报告", "*.json"),),
        )
        if not selected:
            return
        path = Path(selected).resolve()
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            html_path = path.with_suffix(".html")
            if not html_path.is_file():
                write_report_html(report, path)
        except (OSError, json.JSONDecodeError) as exc:
            messagebox.showerror("无法加载报告", str(exc), parent=self.root)
            return
        self.report_path = path
        self.output_file.set(str(path))
        self.last_report_mtime = path.stat().st_mtime
        self._render_report(report)
        self.open_button.configure(state="normal")
        self.status_text.set(f"已加载报告：{path.name}")

    def _append_log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _on_close(self) -> None:
        if self.process and self.process.poll() is None:
            if not messagebox.askyesno("退出", "检测仍在运行。停止检测并退出吗？", parent=self.root):
                return
            self._stop()
        self.trusted_key.set("")
        self.candidate_key.set("")
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    DetectorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
