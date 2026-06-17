package cgep.hipaa.s3_tls_only

import rego.v1

# METADATA
# title: GAP-03 — S3 uploads bucket must deny non-TLS requests
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: high
#   remediation: Add aws_s3_bucket_policy.uploads_tls_only denying s3:* when aws:SecureTransport is false.

resource contains r if { r := input.planned_values.root_module.resources[_] }

has_tls_deny_policy if {
  resource[r]
  r.type == "aws_s3_bucket_policy"
  r.name == "uploads_tls_only"
  policy := r.values.policy
  contains(policy, "aws:SecureTransport")
  contains(policy, "false")
  contains(policy, "Deny")
}

deny contains msg if {
  not has_tls_deny_policy
  msg := "HIPAA 164.312(e)(1) / GAP-03: uploads bucket must deny non-TLS requests with aws:SecureTransport=false."
}
