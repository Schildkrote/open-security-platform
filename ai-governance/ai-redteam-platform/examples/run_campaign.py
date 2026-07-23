"""Demo: run an authorized red-team campaign and print reports."""
from ai_redteam_platform import (
    connect, register_target, set_authorization, MockTarget, SafeRunner,
    technical_report, executive_report, compliance_report, verify_chain,
    redteam_available,
)

conn = connect()
target = register_target(conn, "Demo Assistant", provider="internal", app_type="llm-chatbot", risk_tier="high")
set_authorization(conn, target["id"], "authorized")  # authorization gate

runner = SafeRunner(conn)

print("=== Campaign against an UNGUARDED model ===")
result = runner.run_campaign(target["id"], MockTarget(guarded=False, name="unguarded"))
print(executive_report(result.score))
print(compliance_report(result.score, result.compliance))

print("=== Campaign against a GUARDED model ===")
guarded = runner.run_campaign(target["id"], MockTarget(guarded=True, name="guarded"))
print(f"guarded pass rate: {guarded.score.score:.1%}  risk: {guarded.score.risk_score:.2f}")

print("\nevidence chain valid:", verify_chain(conn)["valid"])
print("ai-redteam-evals embedded engine available:", redteam_available())
