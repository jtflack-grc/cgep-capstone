package cgep.hipaa.s3_versioning

# METADATA
# title: GAP-04 — S3 uploads bucket must enable versioning
# custom:
#   framework: hipaa
#   controls:
#     - "164.308(a)(7)"
#   severity: medium
#   remediation: Add aws_s3_bucket_versioning.uploads with status Enabled.

resource contains r if { r := input.planned_values.root_module.resources[_] }

has_uploads_versioning if {
  resource[r]
  r.type == "aws_s3_bucket_versioning"
  r.name == "uploads"
  cfg := r.values.versioning_configuration[_]
  cfg.status == "Enabled"
}

deny contains msg if {
  not has_uploads_versioning
  msg := "HIPAA 164.308(a)(7) / GAP-04: uploads bucket must have versioning enabled for recoverability."
}
