"""Demo: run a purple-team exercise and print the coverage report."""
from purple_team import coverage_percent, coverage_report, gaps, run_exercise

result = run_exercise()
print(f"Detection coverage: {coverage_percent():.1%}  |  "
      f"exercise detection rate: {result.detection_rate:.1%}  |  gaps: {len(gaps())}\n")
print(coverage_report(result))
