package cgep.hipaa.dynamodb_cmk

import rego.v1

# METADATA
# title: GAP-02 — DynamoDB intake table must use customer CMK
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: Add server_side_encryption with enabled=true and kms_key_arn to aws_dynamodb_table.intake.

resource contains r if { r := input.planned_values.root_module.resources[_] }

has_dynamodb_cmk if {
  resource[r]
  r.type == "aws_dynamodb_table"
  r.name == "intake"
  sse := r.values.server_side_encryption[_]
  sse.enabled == true
  sse.kms_key_arn != ""
}

deny contains msg if {
  not has_dynamodb_cmk
  msg := "HIPAA 164.312(a)(2)(iv) / GAP-02: DynamoDB intake table must use a customer-managed KMS key."
}
