package cgep.hipaa.lambda_resilience

import rego.v1

# METADATA
# title: GAP-06 — Lambda needs reserved concurrency, DLQ, and X-Ray tracing
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(b)"
#   severity: medium
#   remediation: Configure reserved_concurrent_executions, dead_letter_config, and tracing_config on aws_lambda_function.intake.

resource contains r if { r := input.planned_values.root_module.resources[_] }

lambda_has_resilience_controls if {
  resource[r]
  r.type == "aws_lambda_function"
  r.name == "intake"
  r.values.reserved_concurrent_executions > 0
  dlq := r.values.dead_letter_config[_]
  dlq.target_arn != ""
  tracing := r.values.tracing_config[_]
  tracing.mode == "Active"
}

deny contains msg if {
  not lambda_has_resilience_controls
  msg := "HIPAA 164.312(b) / GAP-06: intake Lambda must have reserved concurrency, DLQ, and active X-Ray tracing."
}
