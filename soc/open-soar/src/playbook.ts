import { NODES, type StepContext } from "./nodes.ts";
import { heuristicTriage, type TriageFn } from "./triage.ts";

export interface Step {
  id: string;
  type: string;
  params?: Record<string, unknown>;
  deps?: string[];
}

export interface Playbook {
  id: string;
  name: string;
  steps: Step[];
}

export interface ExecutionResult {
  playbook: string;
  status: "success" | "failed";
  order: string[];
  outputs: Record<string, unknown>;
  errors: Record<string, string>;
  skipped: string[];
}

// validate checks ids are unique, deps exist, and the graph is acyclic.
export function validate(playbook: Playbook): string[] {
  const errors: string[] = [];
  const ids = new Set<string>();
  for (const s of playbook.steps) {
    if (ids.has(s.id)) errors.push(`duplicate step id: ${s.id}`);
    ids.add(s.id);
  }
  for (const s of playbook.steps) {
    for (const d of s.deps ?? []) {
      if (!ids.has(d)) errors.push(`step ${s.id} depends on unknown step ${d}`);
    }
  }
  if (hasCycle(playbook)) errors.push("playbook contains a cycle");
  return errors;
}

function hasCycle(playbook: Playbook): boolean {
  const state = new Map<string, number>(); // 0=unvisited,1=in-progress,2=done
  const byId = new Map(playbook.steps.map((s) => [s.id, s]));
  const visit = (id: string): boolean => {
    const st = state.get(id) ?? 0;
    if (st === 1) return true;
    if (st === 2) return false;
    state.set(id, 1);
    for (const dep of byId.get(id)?.deps ?? []) {
      if (visit(dep)) return true;
    }
    state.set(id, 2);
    return false;
  };
  return playbook.steps.some((s) => visit(s.id));
}

// execute runs the DAG, executing independent steps in parallel per level.
export async function execute(
  playbook: Playbook,
  input: Record<string, unknown>,
  opts: { caseId?: string; triage?: TriageFn } = {},
): Promise<ExecutionResult> {
  const problems = validate(playbook);
  if (problems.length) {
    return { playbook: playbook.name, status: "failed", order: [], outputs: {}, errors: { _graph: problems.join("; ") }, skipped: [] };
  }

  const byId = new Map(playbook.steps.map((s) => [s.id, s]));
  const indegree = new Map(playbook.steps.map((s) => [s.id, (s.deps ?? []).length]));
  const dependents = new Map<string, string[]>();
  for (const s of playbook.steps) {
    for (const d of s.deps ?? []) {
      dependents.set(d, [...(dependents.get(d) ?? []), s.id]);
    }
  }

  const outputs: Record<string, unknown> = {};
  const errors: Record<string, string> = {};
  const skipped: string[] = [];
  const order: string[] = [];
  const failed = new Set<string>();

  let ready = playbook.steps.filter((s) => indegree.get(s.id) === 0).map((s) => s.id);

  while (ready.length) {
    const wave = ready;
    ready = [];
    await Promise.all(
      wave.map(async (id) => {
        const step = byId.get(id)!;
        const blockedDep = (step.deps ?? []).find((d) => failed.has(d) || skipped.includes(d));
        if (blockedDep) {
          skipped.push(id);
          failed.add(id);
          return;
        }
        const ctx: StepContext = {
          input,
          outputs,
          vars: {},
          caseId: opts.caseId,
          triage: opts.triage ?? heuristicTriage,
        };
        const fn = NODES[step.type];
        if (!fn) {
          errors[id] = `unknown node type: ${step.type}`;
          failed.add(id);
          return;
        }
        try {
          outputs[id] = await fn(ctx, step.params ?? {});
          order.push(id);
        } catch (e) {
          errors[id] = (e as Error).message;
          failed.add(id);
        }
      }),
    );
    for (const id of wave) {
      for (const dep of dependents.get(id) ?? []) {
        indegree.set(dep, (indegree.get(dep) ?? 1) - 1);
        if (indegree.get(dep) === 0) ready.push(dep);
      }
    }
  }

  return {
    playbook: playbook.name,
    status: Object.keys(errors).length ? "failed" : "success",
    order,
    outputs,
    errors,
    skipped,
  };
}
