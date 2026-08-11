#!/usr/bin/env node

import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import tls from "node:tls";
import zlib from "node:zlib";

const MAX_CAPTURE_BYTES = 32 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;
const AUTH_ENV = "GPT56_NATIVE_AUTHORIZATION";

function parseArgs(argv) {
  const result = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (!item.startsWith("--")) {
      result._.push(item);
      continue;
    }
    const [rawKey, inline] = item.slice(2).split("=", 2);
    const value = inline ?? argv[++index];
    result[rawKey] = value;
  }
  return result;
}

function ensureInsideCwd(filePath) {
  const absolute = path.resolve(filePath);
  const relative = path.relative(process.cwd(), absolute);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`refusing to write outside ${process.cwd()}`);
  }
  return absolute;
}

function writeLocal(filePath, data) {
  const absolute = ensureInsideCwd(filePath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true });
  fs.writeFileSync(absolute, data, { mode: 0o600 });
}

function parseRawRequest(raw) {
  const separator = raw.indexOf("\r\n\r\n");
  if (separator < 0) throw new Error("incomplete HTTP headers");
  const headerBlock = raw.subarray(0, separator).toString("latin1");
  const lines = headerBlock.split("\r\n");
  const startLine = lines.shift();
  const headers = lines.map((line) => {
    const colon = line.indexOf(":");
    if (colon < 1) throw new Error(`invalid header line: ${line}`);
    return { name: line.slice(0, colon), value: line.slice(colon + 1).trimStart() };
  });
  const lengthHeader = headers.find((header) => header.name.toLowerCase() === "content-length");
  const contentLength = lengthHeader ? Number.parseInt(lengthHeader.value, 10) : 0;
  if (!Number.isSafeInteger(contentLength) || contentLength < 0) throw new Error("invalid Content-Length");
  const end = separator + 4 + contentLength;
  if (raw.length < end) throw new Error("incomplete HTTP body");
  return {
    startLine,
    headers,
    body: raw.subarray(separator + 4, end),
    raw: raw.subarray(0, end),
    complete: raw.length >= end,
  };
}

function redact(request) {
  const sensitive = new Set(["authorization", "chatgpt-account-id", "cookie", "set-cookie"]);
  const headers = request.headers.map(({ name, value }) => ({
    name,
    value: sensitive.has(name.toLowerCase()) ? "<redacted>" : value,
  }));
  let body;
  try {
    body = JSON.parse(request.body.toString("utf8"));
  } catch {
    body = request.body.toString("utf8");
  }
  return { start_line: request.startLine, headers, body, raw_bytes: request.raw.length };
}

async function capture(options, onListen) {
  const listen = options.listen ?? "127.0.0.1:18080";
  const split = listen.lastIndexOf(":");
  const host = listen.slice(0, split);
  const port = Number.parseInt(listen.slice(split + 1), 10);
  const output = options.out ?? "captures/native.raw";
  const report = options.report ?? "captures/native.redacted.json";
  const status = Number.parseInt(options.status ?? "400", 10);

  await new Promise((resolve, reject) => {
    let captured = false;
    const server = net.createServer((socket) => {
      const chunks = [];
      let size = 0;
      socket.setTimeout(30_000, () => socket.destroy(new Error("capture timeout")));
      socket.on("data", (chunk) => {
        chunks.push(chunk);
        size += chunk.length;
        if (size > MAX_CAPTURE_BYTES) {
          socket.destroy(new Error("request exceeds capture limit"));
          return;
        }
        try {
          const request = parseRawRequest(Buffer.concat(chunks, size));
          if (!request.complete) return;
          writeLocal(output, request.raw);
          writeLocal(report, `${JSON.stringify(redact(request), null, 2)}\n`);
          captured = true;
          const payload = Buffer.from('{"error":{"type":"capture_complete","message":"request captured locally"}}');
          const responseHead = Buffer.from(
            `HTTP/1.1 ${status} Capture Complete\r\nContent-Type: application/json\r\nContent-Length: ${payload.length}\r\nConnection: close\r\n\r\n`,
            "latin1",
          );
          socket.end(Buffer.concat([responseHead, payload]));
          console.log(`CAPTURED ${output} (${request.raw.length} bytes)`);
          server.close(resolve);
        } catch (error) {
          if (!String(error.message).startsWith("incomplete HTTP")) reject(error);
        }
      });
      socket.on("error", (error) => {
        if (!captured) reject(error);
      });
    });
    server.on("error", reject);
    server.listen(port, host, () => {
      console.log(`LISTEN ${host}:${port}`);
      try {
        onListen?.();
      } catch (error) {
        reject(error);
      }
    });
  });
}

async function captureLocal(options) {
  const root = process.cwd();
  const codex = path.join(root, "runtime", "codex.exe");
  if (!fs.existsSync(codex)) throw new Error(`missing isolated Codex runtime: ${codex}`);
  const prompt = options.prompt ?? "Reply with exactly: capture-ok";
  let childDone;
  await capture({
    listen: "127.0.0.1:18083",
    out: "captures/native-0.147.0.raw",
    report: "captures/native-0.147.0.redacted.json",
    status: "400",
  }, () => {
    const child = spawn(codex, [
      "exec", "--ephemeral", "--ignore-rules", "--skip-git-repo-check",
      "--sandbox", "read-only", "--json", "-C", root, prompt,
    ], {
      cwd: root,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        CODEX_HOME: path.join(root, "codex-home"),
        TEMP: path.join(root, "tmp"),
        TMP: path.join(root, "tmp"),
        OPENAI_API_KEY: "test-local-only",
      },
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(chunk));
    child.stderr.on("data", (chunk) => stderr.push(chunk));
    childDone = new Promise((resolve, reject) => {
      child.on("error", reject);
      child.on("close", (code) => {
        writeLocal("captures/codex.stdout.jsonl", Buffer.concat(stdout));
        writeLocal("captures/codex.stderr.log", Buffer.concat(stderr));
        resolve(code);
      });
    });
  });
  if (childDone) await childDone;
  forge({
    profile: "captures/native-0.147.0.raw",
    "body-from-profile": "true",
    out: "captures/forged-native.raw",
  });
  compare({ want: "captures/native-0.147.0.raw", got: "captures/forged-native.raw" });
}

function normalizeCodexBody(body) {
  const value = JSON.parse(body.toString("utf8"));
  value.store = false;
  value.stream = true;
  for (const key of [
    "user", "metadata", "prompt_cache_retention", "safety_identifier", "stream_options",
    "max_output_tokens", "max_completion_tokens", "temperature", "top_p",
    "frequency_penalty", "presence_penalty",
  ]) delete value[key];
  if (typeof value.input === "string") {
    value.input = [{ type: "message", role: "user", content: value.input }];
  }
  if (value.reasoning && Object.keys(value.reasoning).length > 0) {
    value.include = Array.isArray(value.include) ? value.include : [];
    if (!value.include.includes("reasoning.encrypted_content")) {
      value.include.push("reasoning.encrypted_content");
    }
  }
  return Buffer.from(JSON.stringify(value));
}

function buildFromProfile(profile, body, overrides) {
  let startLine = profile.startLine;
  if (overrides.path) {
    const parts = startLine.split(" ");
    parts[1] = overrides.path;
    startLine = parts.join(" ");
  }
  const lines = [startLine];
  for (const header of profile.headers) {
    const name = header.name.toLowerCase();
    let value = header.value;
    if (name === "content-length") value = String(body.length);
    if (overrides.headers?.[name] !== undefined) value = overrides.headers[name];
    if (name === "authorization" && overrides.authorization !== undefined) value = overrides.authorization;
    if (name === "host" && overrides.host !== undefined) value = overrides.host;
    if (name === "originator" && overrides.originator !== undefined) value = overrides.originator;
    if (name === "user-agent" && overrides.userAgent !== undefined) value = overrides.userAgent;
    lines.push(`${header.name}: ${value}`);
  }
  return Buffer.concat([Buffer.from(`${lines.join("\r\n")}\r\n\r\n`, "latin1"), body]);
}

function uuid7Like() {
  const bytes = crypto.randomBytes(16);
  let timestamp = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function fixedEnvironmentContext(currentDate) {
  return [
    "<environment_context>",
    "  <cwd>C:\\workspace</cwd>",
    "  <shell>powershell</shell>",
    `  <current_date>${currentDate}</current_date>`,
    "  <timezone>UTC</timezone>",
    "  <filesystem><workspace_roots><root>C:\\workspace</root></workspace_roots><permission_profile type=\"managed\"><file_system type=\"restricted\"><entry access=\"read\"><special>:root</special></entry></file_system></permission_profile></filesystem>",
    "</environment_context>",
  ].join("\n");
}

function messageItem(role, text) {
  return {
    type: "message",
    role,
    id: `msg_${uuid7Like()}`,
    content: [{ type: role === "assistant" ? "output_text" : "input_text", text }],
  };
}

function normalizeProbeMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) {
    throw new Error("probe messages must be a non-empty array");
  }
  const normalized = messages.map((item) => {
    if (!item || !["developer", "user"].includes(item.role) || typeof item.content !== "string") {
      throw new Error("probe messages must contain developer/user role and string content");
    }
    return { role: item.role, content: item.content };
  });
  if (normalized.at(-1).role !== "user") {
    throw new Error("the final probe message must use the user role");
  }
  if (normalized.slice(0, -1).some((item) => item.role !== "developer")) {
    throw new Error("only developer messages may precede the final probe user message");
  }
  return normalized;
}

function sanitizeCapturedText(text) {
  return String(text)
    .replace(/C:\/Users\/[^/]+\/Desktop\/sub2api\/test\/codex-home\//gi, "C:/codex-home/")
    .replace(/[A-Za-z]:\\Users\\[^\\\s<>"']+(?:\\[^\s<>"']+)*/gi, "C:\\workspace")
    .replace(/C:\/Users\/[^/\s<>"']+(?:\/[^\s<>"']+)*/gi, "C:/workspace");
}

function sanitizeCapturedInput(input) {
  for (const item of input) {
    for (const part of item?.content ?? []) {
      if (typeof part?.text === "string") part.text = sanitizeCapturedText(part.text);
    }
  }
  return input;
}

function buildTurnState() {
  const installationId = crypto.randomUUID();
  const sessionId = uuid7Like();
  const turnId = uuid7Like();
  const windowId = `${sessionId}:0`;
  const startedAt = Date.now();
  const base = {
    installation_id: installationId,
    session_id: sessionId,
    thread_id: sessionId,
    turn_id: turnId,
    window_id: windowId,
    request_kind: "turn",
    thread_source: "user",
    sandbox: "none",
  };
  return { installationId, sessionId, turnId, windowId, startedAt, base };
}

function buildProbeBody(profile, options) {
  const value = JSON.parse(profile.body.toString("utf8"));
  const state = buildTurnState();
  const currentDate = options.currentDate ?? new Date().toISOString().slice(0, 10);
  const input = sanitizeCapturedInput(structuredClone(value.input));
  const userIndexes = input
    .map((item, index) => item?.type === "message" && item?.role === "user" ? index : -1)
    .filter((index) => index >= 0);
  if (userIndexes.length < 2) throw new Error("native profile is missing environment/final user messages");
  const environmentIndex = userIndexes.at(-2);
  const finalIndex = userIndexes.at(-1);
  const probeMessages = normalizeProbeMessages(
    options.probeMessages ?? [{ role: "user", content: options.prompt }],
  );
  input[environmentIndex] = messageItem("user", fixedEnvironmentContext(currentDate));
  input[finalIndex] = messageItem("user", probeMessages.at(-1).content);
  for (let index = 0; index < input.length; index += 1) {
    if (index === environmentIndex || index === finalIndex) continue;
    if (input[index]?.type === "message" && input[index]?.id) input[index].id = `msg_${uuid7Like()}`;
  }
  const history = options.history ?? [];
  if (!Array.isArray(history)) throw new Error("history must be an array");
  const historyMessages = history.map((item) => {
    if (!item || !["user", "assistant"].includes(item.role) || typeof item.text !== "string") {
      throw new Error("history items must contain role user/assistant and string text");
    }
    return messageItem(item.role, item.text);
  });
  const probePrefix = probeMessages.slice(0, -1).map((item) => (
    messageItem(item.role, item.content)
  ));
  input.splice(environmentIndex, 0, ...probePrefix);
  input.splice(finalIndex + probePrefix.length, 0, ...historyMessages);
  const headerTurnMetadata = JSON.stringify({
    ...state.base,
    turn_started_at_unix_ms: state.startedAt,
  });
  const bodyTurnMetadata = JSON.stringify({
    ...state.base,
    code_mode_tool_names: {
      apply_patch: { name: "apply_patch", namespace: null },
      shell_command: { name: "shell_command", namespace: null },
      update_plan: { name: "update_plan", namespace: null },
      view_image: { name: "view_image", namespace: null },
    },
    turn_started_at_unix_ms: state.startedAt,
  });
  value.model = options.model;
  value.input = input;
  value.reasoning = { ...(value.reasoning ?? {}), effort: options.effort ?? value.reasoning?.effort ?? "low" };
  value.prompt_cache_key = state.sessionId;
  value.client_metadata = {
    turn_id: state.turnId,
    "x-codex-installation-id": state.installationId,
    "x-codex-turn-metadata": bodyTurnMetadata,
    session_id: state.sessionId,
    thread_id: state.sessionId,
    "x-codex-window-id": state.windowId,
  };
  const body = normalizeCodexBody(Buffer.from(JSON.stringify(value)));
  const headers = {
    "x-codex-window-id": state.windowId,
    "x-codex-turn-metadata": headerTurnMetadata,
    "x-client-request-id": state.sessionId,
    "session-id": state.sessionId,
    "thread-id": state.sessionId,
  };
  return { body, headers, state };
}

function forge(options) {
  const profile = parseRawRequest(fs.readFileSync(options.profile ?? "captures/native.raw"));
  const sourceBody = options["body-from-profile"] === "true"
    ? profile.body
    : fs.readFileSync(options.body ?? "request.json");
  const body = normalizeCodexBody(sourceBody);
  const raw = buildFromProfile(profile, body, {
    authorization: options.authorization,
    host: options.host,
    originator: options.originator,
    userAgent: options["user-agent"],
    path: options.path,
  });
  const output = options.out ?? "captures/forged.raw";
  writeLocal(output, raw);
  console.log(`FORGED ${output} (${raw.length} bytes)`);
}

function canonicalHeaders(headers) {
  const ignored = new Set([
    "authorization", "content-length", "session_id", "conversation_id", "x-request-id",
    "x-codex-window-id", "x-codex-turn-state", "x-codex-turn-metadata",
  ]);
  const result = {};
  for (const { name, value } of headers) {
    const key = name.toLowerCase();
    if (ignored.has(key)) continue;
    (result[key] ??= []).push(value);
  }
  return result;
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function compare(options) {
  const wantRaw = fs.readFileSync(options.want ?? "captures/native.raw");
  const gotRaw = fs.readFileSync(options.got ?? "captures/forged.raw");
  if (wantRaw.equals(gotRaw)) {
    console.log("EXACT: identical raw HTTP bytes");
    return;
  }
  const want = parseRawRequest(wantRaw);
  const got = parseRawRequest(gotRaw);
  const diffs = [];
  if (want.startLine !== got.startLine) diffs.push(`start line: ${want.startLine} != ${got.startLine}`);
  if (JSON.stringify(stable(canonicalHeaders(want.headers))) !== JSON.stringify(stable(canonicalHeaders(got.headers)))) {
    diffs.push("headers differ (dynamic headers excluded)");
  }
  let wantBody = want.body.toString("utf8");
  let gotBody = got.body.toString("utf8");
  try { wantBody = JSON.stringify(stable(JSON.parse(wantBody))); } catch {}
  try { gotBody = JSON.stringify(stable(JSON.parse(gotBody))); } catch {}
  if (wantBody !== gotBody) diffs.push("JSON body differs");
  console.log(`RAW: different (want=${wantRaw.length} bytes got=${gotRaw.length} bytes)`);
  if (diffs.length === 0) {
    console.log("SEMANTIC: identical after redacting dynamic headers and canonicalizing JSON");
    return;
  }
  console.log("SEMANTIC: different");
  for (const diff of diffs) console.log(`- ${diff}`);
  process.exitCode = 1;
}

async function replay(options) {
  const target = options.target ?? "127.0.0.1:18081";
  const split = target.lastIndexOf(":");
  const host = target.slice(0, split);
  const port = Number.parseInt(target.slice(split + 1), 10);
  const raw = fs.readFileSync(options.in ?? "captures/forged.raw");
  await new Promise((resolve, reject) => {
    const socket = net.createConnection({ host, port }, () => socket.write(raw));
    socket.setTimeout(30_000, () => socket.destroy(new Error("replay timeout")));
    socket.on("data", (chunk) => process.stdout.write(chunk));
    socket.on("end", resolve);
    socket.on("error", reject);
  });
}

function parseResponseHead(buffer) {
  const separator = buffer.indexOf("\r\n\r\n");
  if (separator < 0) return null;
  const lines = buffer.subarray(0, separator).toString("latin1").split("\r\n");
  const statusLine = lines.shift();
  const match = /^HTTP\/1\.[01]\s+(\d{3})\s*(.*)$/.exec(statusLine ?? "");
  if (!match) throw new Error(`invalid HTTP response line: ${statusLine}`);
  const headers = {};
  for (const line of lines) {
    const colon = line.indexOf(":");
    if (colon < 1) continue;
    const name = line.slice(0, colon).toLowerCase();
    const value = line.slice(colon + 1).trimStart();
    (headers[name] ??= []).push(value);
  }
  return { status: Number.parseInt(match[1], 10), reason: match[2], headers, bodyOffset: separator + 4 };
}

function decodeChunked(buffer) {
  let offset = 0;
  const chunks = [];
  for (;;) {
    const lineEnd = buffer.indexOf("\r\n", offset);
    if (lineEnd < 0) return null;
    const line = buffer.subarray(offset, lineEnd).toString("ascii").split(";", 1)[0];
    const size = Number.parseInt(line, 16);
    if (!Number.isFinite(size) || size < 0) throw new Error(`invalid chunk size: ${line}`);
    offset = lineEnd + 2;
    if (size === 0) {
      const trailerEnd = buffer.indexOf("\r\n\r\n", offset);
      if (trailerEnd >= 0) return Buffer.concat(chunks);
      if (buffer.length >= offset + 2 && buffer.subarray(offset, offset + 2).equals(Buffer.from("\r\n"))) {
        return Buffer.concat(chunks);
      }
      return null;
    }
    if (buffer.length < offset + size + 2) return null;
    chunks.push(buffer.subarray(offset, offset + size));
    offset += size;
    if (!buffer.subarray(offset, offset + 2).equals(Buffer.from("\r\n"))) {
      throw new Error("invalid chunk terminator");
    }
    offset += 2;
  }
}

function decodeAvailableChunks(buffer) {
  let offset = 0;
  const chunks = [];
  for (;;) {
    const lineEnd = buffer.indexOf("\r\n", offset);
    if (lineEnd < 0) return Buffer.concat(chunks);
    const line = buffer.subarray(offset, lineEnd).toString("ascii").split(";", 1)[0];
    const size = Number.parseInt(line, 16);
    if (!Number.isFinite(size) || size < 0) throw new Error(`invalid chunk size: ${line}`);
    offset = lineEnd + 2;
    if (size === 0 || buffer.length < offset + size + 2) return Buffer.concat(chunks);
    chunks.push(buffer.subarray(offset, offset + size));
    offset += size;
    if (!buffer.subarray(offset, offset + 2).equals(Buffer.from("\r\n"))) {
      throw new Error("invalid chunk terminator");
    }
    offset += 2;
  }
}

function hasTerminalSseEvent(body) {
  const blocks = body.toString("utf8").split(/\r?\n\r?\n/);
  for (const block of blocks.slice(0, -1)) {
    const payload = block.split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trimStart())
      .join("\n");
    if (!payload || payload === "[DONE]") continue;
    try {
      const event = JSON.parse(payload);
      if (["response.completed", "response.incomplete", "response.failed"].includes(event?.type)) return true;
    } catch {
      // The block may be an unrelated non-JSON SSE event.
    }
  }
  return false;
}

function maybeDecompress(body, headers) {
  const encoding = String(headers["content-encoding"]?.[0] ?? "").toLowerCase();
  if (encoding === "gzip") return zlib.gunzipSync(body);
  if (encoding === "deflate") return zlib.inflateSync(body);
  if (encoding === "br") return zlib.brotliDecompressSync(body);
  return body;
}

function proxyFor(target) {
  const noProxy = String(process.env.NO_PROXY ?? process.env.no_proxy ?? "")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  const hostname = target.hostname.toLowerCase();
  if (noProxy.some((item) => item === "*" || hostname === item || hostname.endsWith(item.startsWith(".") ? item : `.${item}`))) {
    return null;
  }
  const value = process.env.HTTPS_PROXY ?? process.env.https_proxy
    ?? process.env.ALL_PROXY ?? process.env.all_proxy
    ?? process.env.HTTP_PROXY ?? process.env.http_proxy;
  return value ? new URL(value) : null;
}

async function openProxyTunnel(proxy, target, targetPort, timeoutMs) {
  return await new Promise((resolve, reject) => {
    const socket = net.createConnection({
      host: proxy.hostname,
      port: Number.parseInt(proxy.port || "80", 10),
    });
    let response = Buffer.alloc(0);
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners("data");
      socket.removeAllListeners("error");
      socket.removeAllListeners("timeout");
      if (error) {
        socket.destroy();
        reject(error);
      } else {
        socket.setTimeout(0);
        resolve(value);
      }
    };
    socket.setTimeout(timeoutMs, () => finish(new Error("proxy CONNECT timeout")));
    socket.on("connect", () => {
      const authority = `${target.hostname}:${targetPort}`;
      const lines = [
        `CONNECT ${authority} HTTP/1.1`,
        `Host: ${authority}`,
        "Proxy-Connection: Keep-Alive",
      ];
      if (proxy.username || proxy.password) {
        const token = Buffer.from(`${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`).toString("base64");
        lines.push(`Proxy-Authorization: Basic ${token}`);
      }
      socket.write(`${lines.join("\r\n")}\r\n\r\n`, "latin1");
    });
    socket.on("data", (chunk) => {
      response = Buffer.concat([response, chunk]);
      if (response.length > 64 * 1024) {
        finish(new Error("proxy CONNECT response exceeds size limit"));
        return;
      }
      const separator = response.indexOf("\r\n\r\n");
      if (separator < 0) return;
      const statusLine = response.subarray(0, separator).toString("latin1").split("\r\n", 1)[0];
      if (!/^HTTP\/1\.[01]\s+200\b/.test(statusLine)) {
        finish(new Error(`proxy CONNECT failed: ${statusLine}`));
        return;
      }
      const remainder = response.subarray(separator + 4);
      if (remainder.length) socket.unshift(remainder);
      finish(null, socket);
    });
    socket.on("error", (error) => finish(error));
  });
}

async function openTlsSocket(target, timeoutMs) {
  const port = Number.parseInt(target.port || "443", 10);
  const proxy = proxyFor(target);
  const tunnel = proxy ? await openProxyTunnel(proxy, target, port, timeoutMs) : null;
  return await new Promise((resolve, reject) => {
    const socket = tls.connect({
      ...(tunnel ? { socket: tunnel } : { host: target.hostname, port }),
      servername: target.hostname,
      ALPNProtocols: ["http/1.1"],
      rejectUnauthorized: true,
    });
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners("secureConnect");
      socket.removeAllListeners("error");
      socket.removeAllListeners("timeout");
      if (error) {
        socket.destroy();
        reject(error);
      } else {
        socket.setTimeout(0);
        resolve(socket);
      }
    };
    socket.setTimeout(timeoutMs, () => finish(new Error("TLS connect timeout")));
    socket.on("secureConnect", () => {
      if (socket.alpnProtocol && socket.alpnProtocol !== "http/1.1") {
        finish(new Error(`unexpected ALPN protocol: ${socket.alpnProtocol}`));
        return;
      }
      finish(null);
    });
    socket.on("error", (error) => finish(error));
  });
}

async function openPlainLoopbackSocket(target, timeoutMs) {
  const hostname = target.hostname.toLowerCase();
  if (!["127.0.0.1", "localhost", "::1", "[::1]"].includes(hostname)) {
    throw new Error("plain HTTP native send is restricted to loopback hosts");
  }
  return await new Promise((resolve, reject) => {
    const socket = net.createConnection({
      host: target.hostname,
      port: Number.parseInt(target.port || "80", 10),
    });
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners("connect");
      socket.removeAllListeners("error");
      socket.removeAllListeners("timeout");
      if (error) {
        socket.destroy();
        reject(error);
      } else {
        socket.setTimeout(0);
        resolve(socket);
      }
    };
    socket.setTimeout(timeoutMs, () => finish(new Error("plain HTTP connect timeout")));
    socket.on("connect", () => finish(null));
    socket.on("error", (error) => finish(error));
  });
}

async function sendRawHttp(target, raw, timeoutMs) {
  const socket = target.protocol === "https:"
    ? await openTlsSocket(target, timeoutMs)
    : target.protocol === "http:"
      ? await openPlainLoopbackSocket(target, timeoutMs)
      : (() => { throw new Error(`unsupported native URL protocol: ${target.protocol}`); })();
  return await new Promise((resolve, reject) => {
    let received = Buffer.alloc(0);
    let head = null;
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(result);
    };
    socket.write(raw);
    socket.setTimeout(timeoutMs, () => finish(new Error("native response timeout")));
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk]);
      if (received.length > MAX_RESPONSE_BYTES) {
        finish(new Error("native response exceeds size limit"));
        return;
      }
      try {
        head ??= parseResponseHead(received);
        if (!head) return;
        const encodedBody = received.subarray(head.bodyOffset);
        const transfer = String(head.headers["transfer-encoding"]?.[0] ?? "").toLowerCase();
        const encoding = String(head.headers["content-encoding"]?.[0] ?? "").toLowerCase();
        let body = null;
        if (transfer.includes("chunked")) {
          if (!encoding) {
            const available = decodeAvailableChunks(encodedBody);
            if (hasTerminalSseEvent(available)) {
              finish(null, { ...head, body: available });
              return;
            }
          }
          body = decodeChunked(encodedBody);
        } else if (head.headers["content-length"]?.[0] !== undefined) {
          const length = Number.parseInt(head.headers["content-length"][0], 10);
          if (encodedBody.length >= length) body = encodedBody.subarray(0, length);
        } else if (!encoding && hasTerminalSseEvent(encodedBody)) {
          body = encodedBody;
        }
        if (body) finish(null, { ...head, body: maybeDecompress(body, head.headers) });
      } catch (error) {
        finish(error);
      }
    });
    socket.on("end", () => {
      if (settled) return;
      try {
        head ??= parseResponseHead(received);
        if (!head) throw new Error("connection ended before response headers");
        const body = maybeDecompress(received.subarray(head.bodyOffset), head.headers);
        finish(null, { ...head, body });
      } catch (error) {
        finish(error);
      }
    });
    socket.on("error", (error) => finish(error));
  });
}

function assertPrivateFieldsAbsent(body) {
  const text = body.toString("utf8");
  const forbidden = [
    /[A-Za-z]:\\Users\\/i,
    /\\\\[^\\\s]+\\Users\\/i,
    /\bsub2api\b/i,
    /\bAppData\b/i,
  ];
  const hit = forbidden.find((pattern) => pattern.test(text));
  if (hit) throw new Error(`privacy scan rejected native body: ${hit}`);
}

function stripAuthorizationHeader(raw) {
  const separator = raw.indexOf(Buffer.from("\r\n\r\n", "ascii"));
  if (separator < 0) throw new Error("native request is missing the header separator");
  const headerLines = raw.subarray(0, separator).toString("latin1").split("\r\n");
  const filtered = headerLines.filter((line, index) => index === 0 || !/^authorization\s*:/i.test(line));
  return Buffer.concat([
    Buffer.from(`${filtered.join("\r\n")}\r\n\r\n`, "latin1"),
    raw.subarray(separator + 4),
  ]);
}

async function sendNative(options) {
  const authorizationValue = process.env[AUTH_ENV];
  if (!authorizationValue) throw new Error(`${AUTH_ENV} is not set`);
  const authorization = /^Bearer\s/i.test(authorizationValue)
    ? authorizationValue
    : `Bearer ${authorizationValue}`;
  const target = new URL(options.url);
  const profile = parseRawRequest(fs.readFileSync(options.profile ?? "native-0.147.0.raw"));
  const stdin = options["input-json"] === "true" || !options["prompt-file"]
    ? fs.readFileSync(0, "utf8")
    : null;
  const probeMessages = options["input-json"] === "true"
    ? JSON.parse(stdin)
    : [{ role: "user", content: options["prompt-file"]
      ? fs.readFileSync(options["prompt-file"], "utf8")
      : stdin }];
  const history = options["history-file"]
    ? JSON.parse(fs.readFileSync(options["history-file"], "utf8"))
    : [];
  const built = buildProbeBody(profile, {
    model: options.model,
    probeMessages,
    history,
    effort: options.effort,
    currentDate: options.date,
  });
  assertPrivateFieldsAbsent(built.body);
  const hostHeader = target.port && target.port !== "443"
    ? `${target.hostname}:${target.port}`
    : target.hostname;
  const requestPath = `${target.pathname || "/"}${target.search}`;
  const raw = buildFromProfile(profile, built.body, {
    authorization,
    host: hostHeader,
    path: requestPath,
    headers: built.headers,
  });
  const result = await sendRawHttp(target, raw, Number.parseInt(options.timeout ?? "120000", 10));
  const safeHeaders = {};
  for (const name of ["content-type", "cache-control", "cf-cache-status", "transfer-encoding"]) {
    if (result.headers[name]) safeHeaders[name] = result.headers[name];
  }
  const report = {
    status: result.status,
    reason: result.reason,
    headers: safeHeaders,
    body: result.body.toString("utf8"),
    request: {
      raw_bytes: raw.length,
      body_bytes: built.body.length,
      body_sha256: crypto.createHash("sha256").update(built.body).digest("hex"),
      history_messages: history.length,
      probe_messages: probeMessages.length,
      reasoning_effort: options.effort ?? "low",
      session_sha256: crypto.createHash("sha256").update(built.state.sessionId).digest("hex"),
      native_profile: path.basename(options.profile ?? "native-0.147.0.raw"),
      stream: true,
    },
  };
  if (options["capture-sanitized-request"] === "true") {
    report.request.raw_without_auth_base64 = stripAuthorizationHeader(raw).toString("base64");
    report.request.auth_header_omitted = true;
  }
  process.stdout.write(`${JSON.stringify(report)}\n`);
}

function buildNative(options) {
  const target = new URL(options.url ?? "https://example.invalid/v1/responses");
  const profile = parseRawRequest(fs.readFileSync(options.profile ?? "native-0.147.0.raw"));
  const probeMessages = options["input-file"]
    ? JSON.parse(fs.readFileSync(options["input-file"], "utf8"))
    : [{ role: "user", content: fs.readFileSync(options["prompt-file"], "utf8") }];
  const history = options["history-file"]
    ? JSON.parse(fs.readFileSync(options["history-file"], "utf8"))
    : [];
  const built = buildProbeBody(profile, {
    model: options.model,
    probeMessages,
    history,
    effort: options.effort,
    currentDate: options.date,
  });
  assertPrivateFieldsAbsent(built.body);
  const hostHeader = target.port && target.port !== "443"
    ? `${target.hostname}:${target.port}`
    : target.hostname;
  const raw = buildFromProfile(profile, built.body, {
    authorization: "Bearer test-local-only",
    host: hostHeader,
    path: `${target.pathname || "/"}${target.search}`,
    headers: built.headers,
  });
  const output = options.out ?? "native-probe.raw";
  writeLocal(output, raw);
  console.log(JSON.stringify({
    output,
    raw_bytes: raw.length,
    body_bytes: built.body.length,
    body_sha256: crypto.createHash("sha256").update(built.body).digest("hex"),
    history_messages: history.length,
    private_fields_absent: true,
  }));
}

function usage() {
  console.error("codex-native-transport.mjs <capture-local|capture|forge|compare|replay|build-native|send-native> [--key value]");
}

const [command, ...argv] = process.argv.slice(2);
const options = parseArgs(argv);
try {
  if (command === "capture-local") await captureLocal(options);
  else if (command === "capture") await capture(options);
  else if (command === "forge") forge(options);
  else if (command === "compare") compare(options);
  else if (command === "replay") await replay(options);
  else if (command === "build-native") buildNative(options);
  else if (command === "send-native") await sendNative(options);
  else {
    usage();
    process.exitCode = 2;
  }
} catch (error) {
  const details = {
    name: error?.name ?? "Error",
    code: error?.code ?? null,
    message: error?.message ?? String(error),
    cause: error?.cause?.message ?? null,
    nested: Array.isArray(error?.errors)
      ? error.errors.map((item) => ({ code: item?.code ?? null, message: item?.message ?? String(item) }))
      : [],
  };
  console.error(`error: ${JSON.stringify(details)}`);
  process.exitCode = 1;
}
