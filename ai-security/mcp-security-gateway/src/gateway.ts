import type { DB } from "./db.ts";
import * as registry from "./registry.ts";
import { PolicyEngine } from "./policy.ts";
import { scanArguments, scanToolDescription } from "./poisoning.ts";
import { injectSecrets } from "./secrets.ts";
import * as audit from "./audit.ts";
import { ERR, error, result, type JsonRpcRequest, type JsonRpcResponse } from "./jsonrpc.ts";

export type ToolExecutor = (
  tool: registry.McpTool,
  args: unknown,
) => Promise<unknown> | unknown;

export interface GatewayOptions {
  allowedDomains?: string[];
  poisonThreshold?: number; // number of signals that triggers a block
  requireAuth?: boolean;
  executor?: ToolExecutor;
}

const mockExecutor: ToolExecutor = (tool, args) => ({
  content: [{ type: "text", text: `executed ${tool.name} with ${JSON.stringify(args)}` }],
});

export class Gateway {
  policy: PolicyEngine;
  opts: Required<Omit<GatewayOptions, "executor">> & { executor: ToolExecutor };

  constructor(db: DB, policy: PolicyEngine, options: GatewayOptions = {}) {
    this.policy = policy;
    this.opts = {
      allowedDomains: options.allowedDomains ?? [],
      poisonThreshold: options.poisonThreshold ?? 1,
      requireAuth: options.requireAuth ?? false,
      executor: options.executor ?? mockExecutor,
    };
  }

  handle(db: DB, req: JsonRpcRequest, principal: string | null): Promise<JsonRpcResponse> | JsonRpcResponse {
    if (req.jsonrpc !== "2.0" || !req.method) {
      return error(req.id ?? null, ERR.INVALID_REQUEST, "invalid JSON-RPC request");
    }
    if (this.opts.requireAuth && !principal) {
      audit.audit(db, { principal: "anonymous", method: req.method, decision: "unauthorized" });
      return error(req.id, ERR.UNAUTHORIZED, "authentication required");
    }

    switch (req.method) {
      case "initialize":
        return result(req.id, { protocolVersion: "2024-11-05", serverInfo: { name: "mcp-security-gateway" } });
      case "tools/list":
        return this.toolsList(db, req, principal);
      case "tools/call":
        return this.toolsCall(db, req, principal);
      default:
        return error(req.id, ERR.METHOD_NOT_FOUND, `unknown method: ${req.method}`);
    }
  }

  private toolsList(db: DB, req: JsonRpcRequest, principal: string | null): JsonRpcResponse {
    const tools = registry.listTools(db, true).map((t) => {
      const signals = scanToolDescription(t.description ?? "", this.opts.allowedDomains);
      return {
        name: t.name,
        description: t.description,
        risk: t.risk,
        poisoned: signals.length >= this.opts.poisonThreshold,
        poison_signals: signals,
      };
    });
    audit.audit(db, { principal: principal ?? undefined, method: "tools/list", decision: "allow" });
    return result(req.id, { tools });
  }

  private async toolsCall(db: DB, req: JsonRpcRequest, principal: string | null): Promise<JsonRpcResponse> {
    const params = (req.params ?? {}) as { name?: string; arguments?: unknown };
    const toolName = params.name;
    if (!toolName) return error(req.id, ERR.INVALID_PARAMS, "missing tool name");

    const tool = registry.getTool(db, toolName);
    if (!tool) return error(req.id, ERR.INVALID_PARAMS, `unknown tool: ${toolName}`);

    const server = registry.getServer(db, tool.server_id);
    if (!server?.allowed || !tool.allowed) {
      audit.audit(db, { principal: principal ?? undefined, method: "tools/call", tool: toolName, decision: "denied", reason: "not allowed" });
      return error(req.id, ERR.FORBIDDEN, "tool not allowed");
    }

    const policyDecision = this.policy.evaluate(toolName, params.arguments);
    if (policyDecision.decision === "deny") {
      audit.audit(db, { principal: principal ?? undefined, method: "tools/call", tool: toolName, decision: "denied", reason: policyDecision.rule });
      return error(req.id, ERR.FORBIDDEN, `denied by policy: ${policyDecision.rule}`);
    }
    if (policyDecision.decision === "approve") {
      audit.audit(db, { principal: principal ?? undefined, method: "tools/call", tool: toolName, decision: "approval_required", reason: policyDecision.rule });
      return result(req.id, { status: "approval_required", rule: policyDecision.rule });
    }

    const signals = scanArguments(params.arguments, this.opts.allowedDomains);
    if (signals.length >= this.opts.poisonThreshold) {
      audit.audit(db, { principal: principal ?? undefined, method: "tools/call", tool: toolName, decision: "poisoned", reason: JSON.stringify(signals) });
      return error(req.id, ERR.POISONED, "possible tool poisoning / prompt injection", signals);
    }

    const injection = injectSecrets(db, params.arguments);
    if (injection.missing.length > 0) {
      return error(req.id, ERR.INVALID_PARAMS, `missing secrets: ${injection.missing.join(",")}`);
    }

    const output = await this.opts.executor(tool, injection.args);
    audit.audit(db, { principal: principal ?? undefined, method: "tools/call", tool: toolName, decision: "allow", reason: `injected:${injection.injected.join(",")}` });
    return result(req.id, { content: output, injected_secrets: injection.injected });
  }
}
