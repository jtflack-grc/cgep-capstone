package cgep.hipaa.lambda_least_privilege

# METADATA
# title: GAP-07 — Lambda IAM policy must be least privilege
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(1)"
#   severity: high
#   remediation: Replace dynamodb:* and s3:* with specific actions such as dynamodb:PutItem and s3:PutObject.

resource contains r if { r := input.planned_values.root_module.resources[_] }

has_least_privilege_policy if {
  resource[r]
  r.type == "aws_iam_role_policy"
  r.name == "lambda_inline"
  policy := r.values.policy
  not contains(policy, "dynamodb:*")
  not contains(policy, "s3:*")
  contains(policy, "dynamodb:PutItem")
  contains(policy, "s3:PutObject")
}

deny contains msg if {
  not has_least_privilege_policy
  msg := "HIPAA 164.312(a)(1) / GAP-07: Lambda IAM policy must not use dynamodb:* or s3:* and must grant only required actions."
}
