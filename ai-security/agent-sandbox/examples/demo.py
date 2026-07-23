"""Demo: run a few commands in the sandbox and print session records."""
from agent_sandbox import EgressPolicy, Limits, Sandbox

with Sandbox(
    egress_policy=EgressPolicy(allowed_domains={"pypi.org"}),
    limits=Limits(cpu_seconds=2),
) as s:
    s.register_tool("greet", lambda args: f"echo hello {args[0]}")

    for cmd in ["echo starting", "sh -c 'echo secret > notes.txt'", "cat notes.txt", "rm -rf /"]:
        rec = s.run(cmd)
        print(f"$ {cmd}\n  allowed={rec.allowed} reason={rec.reason} exit={rec.exit_code} "
              f"out={rec.stdout.strip()!r} changed={rec.files_changed}\n")

    print("tool greet:", s.run_tool("greet", ["agent"]).stdout.strip())

    s.rollback()
    print("after rollback, notes.txt exists:", __import__("os").path.exists(s.jail + "/workspace/notes.txt"))
