package cgep.hipaa.s3_sse_kms

import rego.v1

# METADATA
# title: GAP-01 — S3 uploads bucket must use SSE-KMS with customer CMK
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: Configure aws_s3_bucket_server_side_encryption_configuration.uploads with sse_algorithm aws:kms and a customer-managed kms_master_key_id.

resource contains r if { r := input.planned_values.root_module.resources[_] }

has_uploads_sse_kms if {
  resource[r]
  r.type == "aws_s3_bucket_server_side_encryption_configuration"
  r.name == "uploads"
  rule := r.values.rule[_]
  enc := rule.apply_server_side_encryption_by_default[_]
  enc.sse_algorithm == "aws:kms"
  enc.kms_master_key_id != ""
}

deny contains msg if {
  not has_uploads_sse_kms
  msg := "HIPAA 164.312(a)(2)(iv) / GAP-01: uploads bucket must use SSE-KMS with a customer-managed KMS key."
}
