output "phi_kms_key_arn" {
  value       = aws_kms_key.phi.arn
  description = "Customer-managed KMS key protecting PHI data stores."
}

output "evidence_kms_key_arn" {
  value       = aws_kms_key.evidence.arn
  description = "Customer-managed KMS key protecting the evidence vault."
}

output "evidence_vault_name" {
  value       = aws_s3_bucket.evidence_vault.id
  description = "S3 Object Lock evidence vault name. Set this as GitHub variable EVIDENCE_VAULT."
}

output "cloudtrail_name" {
  value       = aws_cloudtrail.management.name
  description = "Multi-region CloudTrail trail with log-file validation."
}

output "cloudtrail_bucket" {
  value       = aws_s3_bucket.cloudtrail_logs.id
  description = "Dedicated CloudTrail log bucket."
}
