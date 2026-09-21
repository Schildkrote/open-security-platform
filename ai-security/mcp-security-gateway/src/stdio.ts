import { spawn, type ChildProcess } from "node:child_process";
import type { JsonRpcNotification } from "./jsonrpc.ts";
import type { Transport } from "./transport.ts";

// StdioTransport proxies JSON-RPC 2.0 to a local MCP server child process over
// its stdin/stdout, using the MCP stdio framing: newline-delimited JSON
// messages (one UTF-8 JSON object per line, no embedded newlines). Requests are
// correlated by id; notifications (messages without an id) never settle a
// pending request and are surfaced through an optional pass-through callback.
// Server-to-client requests (e.g. sampling) are answered with method-not-found
// so a well-behaved child never hangs waiting on us.
//
// Endpoint format per registered server (MCP-spec-conventional {command,args}):
//   stdio:<command> [args...]                       whitespace-separated form
//   stdio:{"command":"node","args":["server.ts"]}   JSON form (args with spaces)
// Children are spawned WITHOUT a shell so endpoint strings cannot inject shell
// metacharacters. The lifecycle follows the MCP spec: an `initialize` request
// plus a `notifications/initialized` notification once per child, before any
// tools/call is forwarded.

export interface StdioCommand {
  command: string;
  args: string[];
}

export function parseStdioEndpoint(endpoint: string): StdioCommand {
  let spec = endpoint.trim();
  if (spec.startsWith("stdio:")) spec = spec.slice("stdio:".length).trim();
  if (spec.startsWith("{")) {
    const parsed = JSON.parse(spec) as { command?: unknown; args?: unknown };
    if (typeof parsed.command !== "string" || parsed.command === "") {
      throw new Error("mcp stdio: endpoint JSON must include a string 'command'");
    }
    const args = parsed.args ?? [];
    if (!Array.isArray(args) || args.some((a) => typeof a !== "string")) {
      throw new Error("mcp stdio: endpoint JSON 'args' must be an array of strings");
    }
    return { command: parsed.command, args: args as string[] };
  }
  const parts = spec.split(/\s+/).filter(Boolean);
  if (parts.length === 0) throw new Error("mcp stdio: empty command in endpoint");
  return { command: parts[0], args: parts.slice(1) };
}

export interface StdioTransportOptions {
  timeoutMs?: number;
  // Notifications from the child (no id) are passed through to this callback.
  onNotification?: (endpoint: string, notification: JsonRpcNotification) => void;
  env?: Record<string, string | undefined>;
  // Grace period after SIGTERM before escalating to SIGKILL in close().
  killGraceMs?: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;
// Grace period after SIGTERM before SIGKILL. Short: an MCP child is expected to
// exit promptly on stdin EOF, and a hung child must not delay gateway shutdown.
const DEFAULT_KILL_GRACE_MS = 2_000;
// Hard cap on an unterminated stdout frame. Generous (1 MiB) versus any real
// MCP tool response, but bounded so a child emitting an endless newline-free
// stream cannot grow gateway memory without limit.
const MAX_FRAME_BYTES = 1_048_576;
const PROTOCOL_VERSION = "2024-11-05";

type RequestId = number | string;

interface Pending {
  resolve: (value: unknown) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

// One live child process + its in-flight request table.
class StdioSession {
  private child: ChildProcess;
  private nextId = 1;
  private pending = new Map<RequestId, Pending>();
  private buffer = "";
  private dead = false;
  private initPromise: Promise<void> | null = null;
  private endpoint: string;
  private opts: StdioTransportOptions;
  private timeoutMs: number;
  private killGraceMs: number;

  // Note: explicit fields, not TS parameter properties — Node's
  // --experimental-strip-types rejects parameter properties (erasable syntax only).
  constructor(endpoint: string, cmd: StdioCommand, opts: StdioTransportOptions, timeoutMs: number) {
    this.endpoint = endpoint;
    this.opts = opts;
    this.timeoutMs = timeoutMs;
    this.killGraceMs = opts.killGraceMs ?? DEFAULT_KILL_GRACE_MS;
    this.child = spawn(cmd.command, cmd.args, {
      shell: false, // never a shell: endpoint strings must not inject metacharacters
      stdio: ["pipe", "pipe", "inherit"],
      env: { ...(opts.env ?? process.env) },
    });
    // EPIPE once the child is gone; the exit handler rejects in-flight requests.
    this.child.stdin?.on("error", () => undefined);
    this.child.stdout?.setEncoding("utf8");
    this.child.stdout?.on("data", (chunk: string) => this.onData(chunk));
    this.child.on("error", (err: Error) => this.failAll(`spawn failed: ${err.message}`));
    this.child.on("exit", (code, signal) =>
      this.failAll(`child exited (${code ?? signal}) with request(s) in flight`),
    );
  }

  get alive(): boolean {
    return !this.dead;
  }

  private failAll(reason: string): void {
    this.dead = true;
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new Error(`mcp stdio: ${reason}`));
    }
    this.pending.clear();
  }

  private write(msg: unknown): void {
    if (this.dead) throw new Error("mcp stdio: child process is not running");
    // Framing: exactly one JSON object per line; JSON.stringify emits no raw
    // newlines, so this is a complete MCP stdio frame.
    this.child.stdin?.write(`${JSON.stringify(msg)}\n`);
  }

  request(method: string, params?: Record<string, unknown>): Promise<unknown> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`mcp stdio: ${method} timed out after ${this.timeoutMs}ms`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.write({ jsonrpc: "2.0", id, method, params });
      } catch (err) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(err as Error);
      }
    });
  }

  notify(method: string, params?: Record<string, unknown>): void {
    this.write({ jsonrpc: "2.0", method, params });
  }

  // MCP lifecycle: initialize handshake once per child, concurrent callers
  // share the same promise.
  ensureInitialized(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.request("initialize", {
        protocolVersion: PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "mcp-security-gateway", version: "0.1.0" },
      })
        .then(() => {
          this.notify("notifications/initialized");
        })
        .catch((err: unknown) => {
          this.initPromise = null; // allow a retry on the next call
          throw err;
        });
    }
    return this.initPromise;
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    // Guard against an unbounded newline-free stdout from a buggy or hostile
    // child growing gateway memory without limit. A well-formed MCP frame is one
    // JSON object per line, well under this cap; exceeding it means the child is
    // misbehaving, so drop the buffer and fail the session rather than buffer on.
    if (this.buffer.length > MAX_FRAME_BYTES && this.buffer.indexOf("\n") === -1) {
      this.buffer = "";
      this.failAll(`child exceeded ${MAX_FRAME_BYTES}-byte frame cap without a newline`);
      this.closeSync();
      return;
    }
    let nl = this.buffer.indexOf("\n");
    while (nl !== -1) {
      const line = this.buffer.slice(0, nl).replace(/\r$/, "");
      this.buffer = this.buffer.slice(nl + 1);
      nl = this.buffer.indexOf("\n");
      if (line.trim() === "") continue;
      let msg: unknown;
      try {
        msg = JSON.parse(line);
      } catch {
        continue; // non-JSON stdout noise: ignored (spec says stdout is JSON-only)
      }
      this.dispatch(msg);
    }
  }

  private dispatch(msg: unknown): void {
    if (typeof msg !== "object" || msg === null) return;
    const raw = msg as Record<string, unknown>;
    const id = raw.id as RequestId | null | undefined;
    const method = raw.method as string | undefined;

    // Response: carries an id and a result/error, no method. Correlate by id.
    if (id !== undefined && id !== null && method === undefined && ("result" in raw || "error" in raw)) {
      const p = this.pending.get(id);
      if (!p) return; // stale or unknown id
      this.pending.delete(id);
      clearTimeout(p.timer);
      const err = raw.error as { code?: number; message?: string } | undefined;
      if (err) p.reject(new Error(`mcp stdio: ${err.message ?? "error"} (code ${err.code ?? "?"})`));
      else p.resolve(raw.result);
      return;
    }

    // Notification: no id — pass through, never settle a pending request.
    if (method !== undefined && (id === undefined || id === null)) {
      this.opts.onNotification?.(this.endpoint, {
        jsonrpc: "2.0",
        method,
        params: raw.params as Record<string, unknown> | undefined,
      });
      return;
    }

    // Server-to-client request (sampling, roots, …): unsupported here; reply
    // method-not-found so the child can proceed instead of hanging.
    if (method !== undefined && id !== undefined && id !== null) {
      try {
        this.write({
          jsonrpc: "2.0",
          id,
          error: { code: -32601, message: `method not supported by gateway: ${method}` },
        });
      } catch {
        // child already gone; exit handler rejects anything in flight
      }
    }
  }

  close(): void {
    this.failAll("transport closed");
    try {
      this.child.stdin?.end(); // EOF is the spec's own shutdown signal
    } catch {
      // stdin already closed
    }
    if (this.running()) {
      this.child.kill("SIGTERM");
      // Escalate to SIGKILL if the child ignores SIGTERM. unref() so this timer
      // can never hold the event loop open or keep the gateway alive.
      setTimeout(() => {
        if (this.running()) this.child.kill("SIGKILL");
      }, this.killGraceMs).unref();
    }
  }

  // Synchronous shutdown for process-exit hooks, where timers cannot run and
  // there is no opportunity to escalate asynchronously. Trades gracefulness for
  // a guarantee: the child must not outlive the gateway and become an orphan.
  closeSync(): void {
    this.failAll("transport closed");
    try {
      this.child.stdin?.end();
    } catch {
      // stdin already closed
    }
    if (this.running()) this.child.kill("SIGKILL");
  }

  private running(): boolean {
    return this.child.exitCode === null && this.child.signalCode === null;
  }
}

// StdioTransport manages one lazy child session per endpoint and implements the
// same Transport interface as HttpTransport, so it plugs into makeExecutor and
// the gateway's registry/allowlist/policy/poisoning/audit pipeline unchanged.
export class StdioTransport implements Transport {
  private sessions = new Map<string, StdioSession>();
  private spawned = 0;
  private timeoutMs: number;
  private opts: StdioTransportOptions;

  constructor(opts: StdioTransportOptions = {}) {
    this.opts = opts;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  // Total children spawned so far (tests assert denied calls never spawn one).
  get spawnedCount(): number {
    return this.spawned;
  }

  private sessionFor(endpoint: string): StdioSession {
    const existing = this.sessions.get(endpoint);
    if (existing?.alive) return existing;
    const session = new StdioSession(endpoint, parseStdioEndpoint(endpoint), this.opts, this.timeoutMs);
    this.sessions.set(endpoint, session);
    this.spawned += 1;
    return session;
  }

  async callTool(endpoint: string, toolName: string, args: unknown): Promise<unknown> {
    const session = this.sessionFor(endpoint);
    await session.ensureInitialized();
    return session.request("tools/call", { name: toolName, arguments: args ?? {} });
  }

  // Send a JSON-RPC notification to the child (no response is awaited).
  async notify(endpoint: string, method: string, params?: Record<string, unknown>): Promise<void> {
    const session = this.sessionFor(endpoint);
    await session.ensureInitialized();
    session.notify(method, params);
  }

  closeAll(): void {
    for (const session of this.sessions.values()) session.close();
    this.sessions.clear();
  }

  // Synchronous variant for process-exit hooks: timers cannot run there, so
  // children are killed outright rather than asked politely. This is what keeps
  // a dying gateway from leaving orphaned MCP child processes behind.
  closeAllSync(): void {
    for (const session of this.sessions.values()) session.closeSync();
    this.sessions.clear();
  }
}
