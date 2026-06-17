#!/usr/bin/env bash
# CGE-P capstone rapid scaffold generator
# Run from the root of your fork/clone of GRCEngClub/cgep-app-starter.
set -euo pipefail

if [[ ! -d terraform || ! -f terraform/main.tf || ! -f GAPS.md ]]; then
  echo "ERROR: Run this from the root of your cgep-app-starter fork." >&2
  exit 1
fi

mkdir -p policies scripts .github/workflows oidc oscal/components oscal/profiles docs evidence

cat > terraform/grc_baseline.tf <<'HCL'
######################################################################
# CGE-P Capstone — GRC baseline controls around the starter workload
# Primary framework: HIPAA Security Rule
# Closes: GAP-01, GAP-03, GAP-04, GAP-05, GAP-06, GAP-07
# Supports: GAP-02 via the edited aws_dynamodb_table.intake block
######################################################################

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

resource "aws_kms_key" "phi" {
  description             = "CMK for Acme Health PHI data stores"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "${local.name_prefix}-phi-cmk-${local.suffix}"
    Control     = "HIPAA-164.312-a-2-iv"
    DataClass   = "phi"
    EvidenceFor = "GAP-01,GAP-02"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}

resource "aws_kms_key" "evidence" {
  description             = "CMK for CGE-P immutable evidence vault"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = {
    Name        = "${local.name_prefix}-evidence-cmk-${local.suffix}"
    Control     = "HIPAA-164.312-b"
    EvidenceFor = "evidence-vault"
  }
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${local.name_prefix}-evidence-${local.suffix}"
  target_key_id = aws_kms_key.evidence.key_id
}

######################################################################
# GAP-01 / HIPAA 164.312(a)(2)(iv): uploads bucket uses SSE-KMS CMK
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

######################################################################
# GAP-03 / HIPAA 164.312(e)(1): TLS-only bucket access
######################################################################

data "aws_iam_policy_document" "uploads_tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.uploads.arn,
      "${aws_s3_bucket.uploads.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id
  policy = data.aws_iam_policy_document.uploads_tls_only.json
}

######################################################################
# GAP-04 / HIPAA 164.308(a)(7): versioning for recoverability
######################################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

######################################################################
# Evidence vault: Object Lock + versioning + SSE-KMS
######################################################################

resource "aws_s3_bucket" "evidence_vault" {
  bucket              = "${local.name_prefix}-evidence-${local.suffix}"
  object_lock_enabled = true

  tags = {
    Name        = "${local.name_prefix}-evidence-${local.suffix}"
    Purpose     = "signed-immutable-grc-evidence"
    Control     = "HIPAA-164.312-b"
    LockMode    = "GOVERNANCE"
  }
}

resource "aws_s3_bucket_versioning" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence_vault]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_vault" {
  bucket                  = aws_s3_bucket.evidence_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

######################################################################
# CloudTrail: multi-region, log-file-validation on, dedicated bucket
######################################################################

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = "${local.name_prefix}-cloudtrail-${local.suffix}"

  tags = {
    Name        = "${local.name_prefix}-cloudtrail-${local.suffix}"
    Purpose     = "cloudtrail-management-events"
    Control     = "HIPAA-164.312-b"
    EvidenceFor = "audit-controls"
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_logs" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = ["s3:PutObject"]

    resources = [
      "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_logs.json
}

resource "aws_cloudtrail" "management" {
  name                          = "${local.name_prefix}-mgmt-${local.suffix}"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]

  tags = {
    Control     = "HIPAA-164.312-b"
    EvidenceFor = "audit-controls"
  }
}

######################################################################
# GAP-05: Lambda inside starter VPC without NAT Gateway cost
# Gateway endpoints are free; they let the VPC Lambda reach S3/DynamoDB.
######################################################################

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${local.name_prefix}-private-rt"
    EvidenceFor = "GAP-05"
  }
}

resource "aws_route_table_association" "private" {
  count          = length(aws_subnet.private)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Name        = "${local.name_prefix}-s3-endpoint"
    EvidenceFor = "GAP-05"
  }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Name        = "${local.name_prefix}-dynamodb-endpoint"
    EvidenceFor = "GAP-05"
  }
}

resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg-${local.suffix}"
  description = "Lambda egress to AWS service endpoints only; no ingress"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "Allow outbound to AWS service endpoints"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${local.name_prefix}-lambda-sg-${local.suffix}"
    EvidenceFor = "GAP-05"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

######################################################################
# GAP-06: reserved concurrency, DLQ, and X-Ray
######################################################################

resource "aws_sqs_queue" "lambda_dlq" {
  name                      = "${local.name_prefix}-lambda-dlq-${local.suffix}"
  message_retention_seconds = 1209600
  kms_master_key_id         = aws_kms_key.phi.arn

  tags = {
    Name        = "${local.name_prefix}-lambda-dlq-${local.suffix}"
    EvidenceFor = "GAP-06"
    Control     = "operational-resilience"
  }
}

resource "aws_iam_role_policy_attachment" "lambda_xray" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}
HCL

cat > terraform/outputs_grc.tf <<'HCL'
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
HCL

python3 <<'PY'
from pathlib import Path

p = Path('terraform/main.tf')
text = p.read_text()

def find_block(s, header):
    start = s.find(header)
    if start == -1:
        raise SystemExit(f"Could not find block header: {header}")
    brace = s.find('{', start)
    if brace == -1:
        raise SystemExit(f"Could not find opening brace for: {header}")
    depth = 0
    in_str = False
    esc = False
    for i in range(brace, len(s)):
        c = s[i]
        if in_str:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return start, i + 1
    raise SystemExit(f"Could not find closing brace for: {header}")

replacements = {
'resource "aws_dynamodb_table" "intake"': r'''resource "aws_dynamodb_table" "intake" {
  name         = "${local.name_prefix}-submissions-${local.suffix}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  # GAP-02 closed: PHI table uses a customer-managed KMS key.
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.phi.arn
  }

  tags = {
    EvidenceFor = "GAP-02"
    Control     = "HIPAA-164.312-a-2-iv"
  }
}''',
'resource "aws_iam_role_policy" "lambda_inline"': r'''resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id

  # GAP-07 closed: least privilege replaces dynamodb:* and s3:*.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteSubmissionsOnly"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Sid      = "WriteUploadObjectsOnly"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.uploads.arn}/uploads/*"
      },
      {
        Sid      = "SendToDeadLetterQueue"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.lambda_dlq.arn
      },
      {
        Sid    = "UsePhiKmsKeyForWrites"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}''',
'resource "aws_lambda_function" "intake"': r'''resource "aws_lambda_function" "intake" {
  function_name = "${local.name_prefix}-handler-${local.suffix}"
  role          = aws_iam_role.lambda.arn
  handler       = "handler.handler"
  runtime       = "python3.12"

  filename         = data.archive_file.handler.output_path
  source_code_hash = data.archive_file.handler.output_base64sha256
  timeout          = 10

  reserved_concurrent_executions = 10

  environment {
    variables = {
      INTAKE_TABLE  = aws_dynamodb_table.intake.name
      UPLOAD_BUCKET = aws_s3_bucket.uploads.id
    }
  }

  # GAP-05 closed: Lambda runs inside the starter VPC private subnets.
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }

  # GAP-06 closed: failed async events route to a DLQ.
  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }

  # GAP-06 closed: tracing enabled for operational visibility.
  tracing_config {
    mode = "Active"
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy_attachment.lambda_vpc,
    aws_iam_role_policy_attachment.lambda_xray,
    aws_vpc_endpoint.s3,
    aws_vpc_endpoint.dynamodb
  ]

  tags = {
    EvidenceFor = "GAP-05,GAP-06,GAP-07"
  }
}'''
}

for header, repl in replacements.items():
    start, end = find_block(text, header)
    text = text[:start] + repl + text[end:]

p.write_text(text)
PY

cat > policies/hipaa_s3_sse_kms.rego <<'REGO'
package cgep.hipaa.s3_sse_kms

# METADATA
# title: GAP-01 — S3 uploads bucket must use SSE-KMS with customer CMK
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: Configure aws_s3_bucket_server_side_encryption_configuration.uploads with sse_algorithm aws:kms and a customer-managed kms_master_key_id.

resource(r) { r := input.planned_values.root_module.resources[_] }

has_uploads_sse_kms {
  resource(r)
  r.type == "aws_s3_bucket_server_side_encryption_configuration"
  r.name == "uploads"
  rule := r.values.rule[_]
  enc := rule.apply_server_side_encryption_by_default[_]
  enc.sse_algorithm == "aws:kms"
  enc.kms_master_key_id != ""
}

deny[msg] {
  not has_uploads_sse_kms
  msg := "HIPAA 164.312(a)(2)(iv) / GAP-01: uploads bucket must use SSE-KMS with a customer-managed KMS key."
}
REGO

cat > policies/hipaa_s3_sse_kms_test.rego <<'REGO'
package cgep.hipaa.s3_sse_kms

test_pass_sse_kms {
  not deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_s3_bucket_server_side_encryption_configuration","name":"uploads","values":{"rule":[{"apply_server_side_encryption_by_default":[{"sse_algorithm":"aws:kms","kms_master_key_id":"arn:aws:kms:us-east-1:111122223333:key/example"}]}]}}]}}}
}

test_fail_missing_sse_kms {
  deny[_] with input as {"planned_values":{"root_module":{"resources":[]}}}
}
REGO

cat > policies/hipaa_dynamodb_cmk.rego <<'REGO'
package cgep.hipaa.dynamodb_cmk

# METADATA
# title: GAP-02 — DynamoDB intake table must use customer CMK
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(2)(iv)"
#   severity: high
#   remediation: Add server_side_encryption with enabled=true and kms_key_arn to aws_dynamodb_table.intake.

resource(r) { r := input.planned_values.root_module.resources[_] }

has_dynamodb_cmk {
  resource(r)
  r.type == "aws_dynamodb_table"
  r.name == "intake"
  sse := r.values.server_side_encryption[_]
  sse.enabled == true
  sse.kms_key_arn != ""
}

deny[msg] {
  not has_dynamodb_cmk
  msg := "HIPAA 164.312(a)(2)(iv) / GAP-02: DynamoDB intake table must use a customer-managed KMS key."
}
REGO

cat > policies/hipaa_dynamodb_cmk_test.rego <<'REGO'
package cgep.hipaa.dynamodb_cmk

test_pass_dynamodb_cmk {
  not deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_dynamodb_table","name":"intake","values":{"server_side_encryption":[{"enabled":true,"kms_key_arn":"arn:aws:kms:us-east-1:111122223333:key/example"}]}}]}}}
}

test_fail_dynamodb_no_cmk {
  deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_dynamodb_table","name":"intake","values":{}}]}}}
}
REGO

cat > policies/hipaa_s3_tls_only.rego <<'REGO'
package cgep.hipaa.s3_tls_only

# METADATA
# title: GAP-03 — S3 uploads bucket must deny non-TLS requests
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: high
#   remediation: Add aws_s3_bucket_policy.uploads_tls_only denying s3:* when aws:SecureTransport is false.

resource(r) { r := input.planned_values.root_module.resources[_] }

has_tls_deny_policy {
  resource(r)
  r.type == "aws_s3_bucket_policy"
  r.name == "uploads_tls_only"
  policy := r.values.policy
  contains(policy, "aws:SecureTransport")
  contains(policy, "false")
  contains(policy, "Deny")
}

deny[msg] {
  not has_tls_deny_policy
  msg := "HIPAA 164.312(e)(1) / GAP-03: uploads bucket must deny non-TLS requests with aws:SecureTransport=false."
}
REGO

cat > policies/hipaa_s3_tls_only_test.rego <<'REGO'
package cgep.hipaa.s3_tls_only

test_pass_tls_deny {
  not deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_s3_bucket_policy","name":"uploads_tls_only","values":{"policy":"{\"Effect\":\"Deny\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}"}}]}}}
}

test_fail_no_tls_deny {
  deny[_] with input as {"planned_values":{"root_module":{"resources":[]}}}
}
REGO

cat > policies/hipaa_s3_versioning.rego <<'REGO'
package cgep.hipaa.s3_versioning

# METADATA
# title: GAP-04 — S3 uploads bucket must enable versioning
# custom:
#   framework: hipaa
#   controls:
#     - "164.308(a)(7)"
#   severity: medium
#   remediation: Add aws_s3_bucket_versioning.uploads with status Enabled.

resource(r) { r := input.planned_values.root_module.resources[_] }

has_uploads_versioning {
  resource(r)
  r.type == "aws_s3_bucket_versioning"
  r.name == "uploads"
  cfg := r.values.versioning_configuration[_]
  cfg.status == "Enabled"
}

deny[msg] {
  not has_uploads_versioning
  msg := "HIPAA 164.308(a)(7) / GAP-04: uploads bucket must have versioning enabled for recoverability."
}
REGO

cat > policies/hipaa_s3_versioning_test.rego <<'REGO'
package cgep.hipaa.s3_versioning

test_pass_versioning {
  not deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_s3_bucket_versioning","name":"uploads","values":{"versioning_configuration":[{"status":"Enabled"}]}}]}}}
}

test_fail_no_versioning {
  deny[_] with input as {"planned_values":{"root_module":{"resources":[]}}}
}
REGO

cat > policies/hipaa_lambda_vpc.rego <<'REGO'
package cgep.hipaa.lambda_vpc

# METADATA
# title: GAP-05 — Lambda must run inside the starter VPC
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: medium
#   remediation: Add vpc_config to aws_lambda_function.intake referencing starter private subnets and a hardened security group.

resource(r) { r := input.planned_values.root_module.resources[_] }

lambda_has_vpc_config {
  resource(r)
  r.type == "aws_lambda_function"
  r.name == "intake"
  vpc := r.values.vpc_config[_]
  count(vpc.subnet_ids) > 0
  count(vpc.security_group_ids) > 0
}

deny[msg] {
  not lambda_has_vpc_config
  msg := "HIPAA 164.312(e)(1) / GAP-05: intake Lambda must run inside the starter VPC private subnets."
}
REGO

cat > policies/hipaa_lambda_vpc_test.rego <<'REGO'
package cgep.hipaa.lambda_vpc

test_pass_lambda_vpc {
  not deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_lambda_function","name":"intake","values":{"vpc_config":[{"subnet_ids":["subnet-1"],"security_group_ids":["sg-1"]}]}}]}}}
}

test_fail_lambda_no_vpc {
  deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_lambda_function","name":"intake","values":{}}]}}}
}
REGO

cat > policies/hipaa_lambda_resilience.rego <<'REGO'
package cgep.hipaa.lambda_resilience

# METADATA
# title: GAP-06 — Lambda needs reserved concurrency, DLQ, and X-Ray tracing
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(b)"
#   severity: medium
#   remediation: Configure reserved_concurrent_executions, dead_letter_config, and tracing_config on aws_lambda_function.intake.

resource(r) { r := input.planned_values.root_module.resources[_] }

lambda_has_resilience_controls {
  resource(r)
  r.type == "aws_lambda_function"
  r.name == "intake"
  r.values.reserved_concurrent_executions > 0
  dlq := r.values.dead_letter_config[_]
  dlq.target_arn != ""
  tracing := r.values.tracing_config[_]
  tracing.mode == "Active"
}

deny[msg] {
  not lambda_has_resilience_controls
  msg := "HIPAA 164.312(b) / GAP-06: intake Lambda must have reserved concurrency, DLQ, and active X-Ray tracing."
}
REGO

cat > policies/hipaa_lambda_resilience_test.rego <<'REGO'
package cgep.hipaa.lambda_resilience

test_pass_lambda_resilience {
  not deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_lambda_function","name":"intake","values":{"reserved_concurrent_executions":10,"dead_letter_config":[{"target_arn":"arn:aws:sqs:us-east-1:111122223333:q"}],"tracing_config":[{"mode":"Active"}]}}]}}}
}

test_fail_lambda_no_resilience {
  deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_lambda_function","name":"intake","values":{"reserved_concurrent_executions":-1}}]}}}
}
REGO

cat > policies/hipaa_lambda_least_privilege.rego <<'REGO'
package cgep.hipaa.lambda_least_privilege

# METADATA
# title: GAP-07 — Lambda IAM policy must be least privilege
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(a)(1)"
#   severity: high
#   remediation: Replace dynamodb:* and s3:* with specific actions such as dynamodb:PutItem and s3:PutObject.

resource(r) { r := input.planned_values.root_module.resources[_] }

has_least_privilege_policy {
  resource(r)
  r.type == "aws_iam_role_policy"
  r.name == "lambda_inline"
  policy := r.values.policy
  not contains(policy, "dynamodb:*")
  not contains(policy, "s3:*")
  contains(policy, "dynamodb:PutItem")
  contains(policy, "s3:PutObject")
}

deny[msg] {
  not has_least_privilege_policy
  msg := "HIPAA 164.312(a)(1) / GAP-07: Lambda IAM policy must not use dynamodb:* or s3:* and must grant only required actions."
}
REGO

cat > policies/hipaa_lambda_least_privilege_test.rego <<'REGO'
package cgep.hipaa.lambda_least_privilege

test_pass_least_privilege {
  not deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_iam_role_policy","name":"lambda_inline","values":{"policy":"{\"Action\":[\"dynamodb:PutItem\",\"s3:PutObject\"]}"}}]}}}
}

test_fail_wildcard_privileges {
  deny[_] with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_iam_role_policy","name":"lambda_inline","values":{"policy":"{\"Action\":[\"dynamodb:*\",\"s3:*\"]}"}}]}}}
}
REGO

cat > oidc/main.tf <<'HCL'
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "github_owner" {
  type        = string
  description = "GitHub org/user that owns the capstone repo."
}

variable "github_repo" {
  type        = string
  description = "GitHub repo name for the capstone."
}

data "aws_caller_identity" "current" {}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "grc_gate" {
  name                 = "cgep-grc-gate"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_owner}/${var.github_repo}:*"
          }
        }
      }
    ]
  })

  tags = {
    Purpose = "CGE-P capstone GitHub Actions OIDC role"
  }
}

# Deliberately broad for a disposable single-purpose sandbox.
# WRITEUP.md documents this as a 30-day lab trade-off; production would scope this down.
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "role_arn" {
  value = aws_iam_role.grc_gate.arn
}
HCL

cat > .github/workflows/grc-gate.yml <<'YAML'
name: grc-gate

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  id-token: write
  contents: read
  pull-requests: write

env:
  AWS_REGION: us-east-1
  TF_WORKING_DIR: terraform

jobs:
  grc-gate:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Configure AWS credentials via GitHub OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ vars.AWS_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.6.6
          terraform_wrapper: false

      - name: Install Conftest
        run: |
          curl -fsSL https://github.com/open-policy-agent/conftest/releases/download/v0.50.0/conftest_0.50.0_Linux_x86_64.tar.gz | sudo tar -xz -C /usr/local/bin conftest
          conftest --version

      - name: Install OPA
        run: |
          curl -fsSL -o opa https://openpolicyagent.org/downloads/v0.60.0/opa_linux_amd64_static
          chmod +x opa
          sudo mv opa /usr/local/bin/opa
          opa version

      - name: Install tfsec
        run: |
          curl -fsSL https://github.com/aquasecurity/tfsec/releases/download/v1.28.14/tfsec-linux-amd64 -o tfsec
          chmod +x tfsec
          sudo mv tfsec /usr/local/bin/tfsec
          tfsec --version

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3
        with:
          cosign-release: v2.2.4

      - name: Plan the Terraform
        id: plan
        working-directory: ${{ env.TF_WORKING_DIR }}
        run: |
          set -euo pipefail
          mkdir -p ../evidence
          terraform init -input=false
          terraform fmt -check -recursive
          terraform validate
          terraform plan -out=tfplan -no-color 2>&1 | tee ../evidence/plan.txt
          terraform show -json tfplan > ../evidence/plan.json
          terraform version > ../evidence/terraform-version.txt
          git log -1 --pretty=full > ../evidence/commit.txt

      - name: Policy check with Conftest
        id: policy
        if: always()
        run: |
          set -euo pipefail
          mkdir -p evidence
          opa test ./policies | tee evidence/opa-test.txt
          conftest test --policy policies --output=json evidence/plan.json > evidence/opa-results.json || true
          python3 - <<'PY'
          import json, os
          data = json.load(open('evidence/opa-results.json'))
          failures = []
          for result in data:
              failures.extend(result.get('failures') or [])
          print(f"conftest policy failures: {len(failures)}")
          with open('evidence/policy-status.txt','w') as f:
              f.write('failed\n' if failures else 'passed\n')
          with open(os.environ['GITHUB_ENV'],'a') as f:
              f.write(f"POLICY_FAILED={'true' if failures else 'false'}\n")
          PY

      - name: Additional scan with tfsec
        id: tfsec
        if: always()
        run: |
          set -euo pipefail
          tfsec terraform --format sarif --out evidence/tfsec.sarif || true
          echo "tfsec output captured; Rego policies are the capstone blocking gate." | tee evidence/tfsec-note.txt

      - name: Apply on merge to main
        id: apply
        if: github.event_name == 'push' && github.ref == 'refs/heads/main' && env.POLICY_FAILED == 'false'
        working-directory: ${{ env.TF_WORKING_DIR }}
        run: |
          set -euo pipefail
          terraform apply -auto-approve tfplan 2>&1 | tee ../evidence/apply.txt
          terraform show -json > ../evidence/state.json
          terraform output -json > ../evidence/outputs.json

      - name: Record non-apply context
        if: always()
        run: |
          if [[ ! -f evidence/apply.txt ]]; then
            echo "Apply did not run. Expected for pull_request events or failed policy gates." > evidence/apply.txt
          fi
          if [[ ! -f evidence/state.json ]]; then
            echo "{}" > evidence/state.json
          fi
          if [[ ! -f evidence/outputs.json ]]; then
            echo "{}" > evidence/outputs.json
          fi

      - name: Sign evidence bundle with Cosign
        id: sign
        if: always()
        run: |
          set -euo pipefail
          BUNDLE="evidence-${GITHUB_RUN_ID}-${GITHUB_SHA}.tar.gz"
          tar czf "${BUNDLE}" evidence
          sha256sum "${BUNDLE}" | awk '{print $1}' > "${BUNDLE}.sha256"
          cosign sign-blob --yes --bundle "${BUNDLE}.sig.bundle" "${BUNDLE}"
          echo "BUNDLE=${BUNDLE}" >> "$GITHUB_ENV"

      - name: Upload signed bundle to evidence vault
        id: upload
        if: always()
        env:
          VAULT: ${{ vars.EVIDENCE_VAULT }}
        run: |
          set -euo pipefail
          if [[ -z "${VAULT}" ]]; then
            echo "EVIDENCE_VAULT repo variable is not set." >&2
            exit 1
          fi
          KEY_PREFIX="runs/${GITHUB_RUN_ID}"
          aws s3 cp "${BUNDLE}" "s3://${VAULT}/${KEY_PREFIX}/${BUNDLE}"
          aws s3 cp "${BUNDLE}.sha256" "s3://${VAULT}/${KEY_PREFIX}/${BUNDLE}.sha256"
          aws s3 cp "${BUNDLE}.sig.bundle" "s3://${VAULT}/${KEY_PREFIX}/${BUNDLE}.sig.bundle"
          VERSION_ID=$(aws s3api head-object --bucket "${VAULT}" --key "${KEY_PREFIX}/${BUNDLE}" --query VersionId --output text)
          cat > receipt.json <<JSON
          {
            "run_id": "${GITHUB_RUN_ID}",
            "commit_sha": "${GITHUB_SHA}",
            "vault": "${VAULT}",
            "key": "${KEY_PREFIX}/${BUNDLE}",
            "version_id": "${VERSION_ID}",
            "bundle": "${BUNDLE}",
            "sha256_file": "${BUNDLE}.sha256",
            "sigstore_bundle": "${BUNDLE}.sig.bundle"
          }
          JSON
          aws s3 cp receipt.json "s3://${VAULT}/${KEY_PREFIX}/receipt.json"
          cp receipt.json evidence/receipt.json

      - name: Enforce gate result
        if: always()
        run: |
          set -euo pipefail
          STATUS=$(cat evidence/policy-status.txt 2>/dev/null || echo failed)
          if [[ "${STATUS}" != "passed" ]]; then
            echo "Policy gate failed. Evidence was still signed and uploaded."
            exit 1
          fi
          echo "Policy gate passed."
YAML

cat > scripts/verify-evidence.sh <<'BASH'
#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${1:?usage: verify-evidence.sh RUN_ID --vault BUCKET [--profile PROFILE]}"
shift || true
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault) VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT" >&2; exit 2; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
PREFIX="runs/${RUN_ID}"
aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz" --include "evidence-*.tar.gz.sha256" \
  --include "evidence-*.tar.gz.sig.bundle" --include "receipt.json"
BUNDLE=$(ls evidence-*.tar.gz | head -1)
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$(sha256sum "${BUNDLE}" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA mismatch"; exit 1; }
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}"
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ "$RETAIN_UNTIL" > "$NOW" ]] || { echo "FAIL: retention expired"; exit 1; }
echo "CHAIN INTACT for run ${RUN_ID}"
BASH
chmod +x scripts/verify-evidence.sh

cat > scripts/render_oscal.py <<'PY'
#!/usr/bin/env python3
import json, os, uuid
from datetime import datetime, timezone
from pathlib import Path

vault = os.environ.get("EVIDENCE_VAULT", "REPLACE_WITH_EVIDENCE_VAULT")
run_id = os.environ.get("RUN_ID", "REPLACE_WITH_RUN_ID")
sha = os.environ.get("COMMIT_SHA", "REPLACE_WITH_COMMIT_SHA")
repo = os.environ.get("GITHUB_REPOSITORY", "REPLACE_WITH_OWNER_REPO")
now = datetime.now(timezone.utc).isoformat()
bundle = f"evidence-{run_id}-{sha}.tar.gz"
evidence_href = f"s3://{vault}/runs/{run_id}/{bundle}"
source = "https://csrc.nist.gov/pubs/sp/800/66/r2/final"

def u(): return str(uuid.uuid4())

def req(control_id, desc, resources):
    return {
        "uuid": u(),
        "control-id": control_id,
        "description": desc,
        "props": [
            {"name": "framework", "value": "HIPAA Security Rule"},
            {"name": "implementation-status", "value": "implemented"},
            *[{"name":"terraform-resource", "value": r} for r in resources]
        ],
        "links": [
            {"rel":"evidence", "href": evidence_href, "text":"Signed GitHub Actions evidence bundle containing plan.json, opa-results.json, state.json/apply context, signature, and receipt."}
        ]
    }

component = {
  "component-definition": {
    "uuid": u(),
    "metadata": {
      "title": "Acme Health Patient Intake API — CGE-P Capstone Component",
      "last-modified": now,
      "version": "1.0.0",
      "oscal-version": "1.1.3",
      "parties": [{"uuid": u(), "type": "organization", "name": "Acme Health / John Flack CGE-P Capstone"}]
    },
    "components": [{
      "uuid": u(),
      "type": "software",
      "title": "Acme Health Patient Intake API governed baseline",
      "description": "Terraform, policy-as-code, GitHub Actions, signed evidence, and OSCAL wrapper around the CGE-P patient intake starter workload.",
      "purpose": "Make the inherited patient intake API audit-defensible under the HIPAA Security Rule without rewriting the application.",
      "control-implementations": [{
        "uuid": u(),
        "source": source,
        "description": "HIPAA Security Rule implementation statements using NIST SP 800-66 Rev. 2 as the HIPAA implementation reference. HIPAA section IDs are carried as control-id values and props.",
        "implemented-requirements": [
          req("164.312(a)(2)(iv)", "PHI at rest is protected with customer-managed KMS keys for S3 uploads and DynamoDB submissions.", ["aws_kms_key.phi", "aws_s3_bucket_server_side_encryption_configuration.uploads", "aws_dynamodb_table.intake"]),
          req("164.312(e)(1)", "S3 uploads deny non-TLS requests and the Lambda runs inside the starter VPC private subnets with AWS service endpoints.", ["aws_s3_bucket_policy.uploads_tls_only", "aws_lambda_function.intake", "aws_vpc_endpoint.s3", "aws_vpc_endpoint.dynamodb"]),
          req("164.308(a)(7)", "S3 uploads enable versioning to support recoverability of PHI objects.", ["aws_s3_bucket_versioning.uploads"]),
          req("164.312(a)(1)", "The Lambda execution role uses least-privilege permissions instead of dynamodb:* and s3:*.", ["aws_iam_role_policy.lambda_inline"]),
          req("164.312(b)", "Audit controls are supported by multi-region CloudTrail, log-file validation, Lambda tracing, and signed immutable pipeline evidence.", ["aws_cloudtrail.management", "aws_s3_bucket.evidence_vault", "aws_s3_bucket_object_lock_configuration.evidence_vault", "aws_lambda_function.intake"])
        ]
      }]
    }]
  }
}

profile = {
  "profile": {
    "uuid": u(),
    "metadata": {
      "title": "Acme Health CGE-P HIPAA control selection",
      "last-modified": now,
      "version": "1.0.0",
      "oscal-version": "1.1.3"
    },
    "imports": [{
      "href": source,
      "include-controls": [{"with-ids": ["164.312(a)(2)(iv)", "164.312(e)(1)", "164.308(a)(7)", "164.312(a)(1)", "164.312(b)"]}]
    }],
    "merge": {"as-is": True}
  }
}

Path("oscal/components").mkdir(parents=True, exist_ok=True)
Path("oscal/profiles").mkdir(parents=True, exist_ok=True)
Path("oscal/components/acme-health-intake-component-definition.json").write_text(json.dumps(component, indent=2))
Path("oscal/profiles/hipaa-minimum-profile.json").write_text(json.dumps(profile, indent=2))
print("Wrote OSCAL component and profile")
PY
chmod +x scripts/render_oscal.py

cat > docs/design.md <<'MD'
# CGE-P Capstone Design Spine

Primary framework: HIPAA Security Rule.

Rationale: Acme Health's Patient Intake API ingests patient submissions and optional attachments, so PHI protection is the most direct compliance objective. SOC 2 and CMMC are valid secondary narratives, but HIPAA is the clearest primary framework for a 30-day GRC engineering sprint.

Region: us-east-1.

Evidence vault: S3 Object Lock in GOVERNANCE mode with 1-day retention for lab cleanup. Production would use COMPLIANCE mode and a longer retention period.

Account model: Single AWS sandbox account. Production would separate workload and evidence-vault accounts.

Pipeline behavior: Plan and policy-check on pull requests; apply on merge to main; sign and upload evidence on every run.

Gaps closed technically: GAP-01, GAP-02, GAP-03, GAP-04, GAP-05, GAP-06, GAP-07.

Gap deferred: GAP-08. API Gateway logging/throttling/WAF is a valid next sprint, but this submission prioritizes PHI encryption, VPC placement, least privilege, recoverability, operational resilience, CloudTrail, and signed immutable evidence.
MD

cat > WRITEUP.md <<'MD'
# CGE-P Capstone Write-up — Acme Health Patient Intake API

Primary framework: **HIPAA Security Rule**. I chose HIPAA because the inherited Patient Intake API handles patient submissions and optional attachments, making PHI confidentiality, transmission security, auditability, and recoverability the most direct GRC engineering concerns.

## Design decisions

I kept the starter workload intact and wrapped it with a GRC baseline rather than rewriting the application. The design uses Terraform for enforceable infrastructure state, Rego/Conftest for policy gates, GitHub Actions for continuous evidence generation, Cosign keyless signing for chain of custody, S3 Object Lock for preservation, and OSCAL for traceability.

The capstone uses `us-east-1`, a single AWS sandbox account, and an S3 evidence vault using Object Lock in `GOVERNANCE` mode with one-day retention. In production I would use a separate evidence account and longer `COMPLIANCE` retention, but the single-account `GOVERNANCE` model is appropriate for a short-lived lab and avoids accidental retention/cost issues.

## Control coverage and gap remediation

| Gap | HIPAA control | Remediation |
|---|---|---|
| GAP-01 | 164.312(a)(2)(iv) | S3 uploads bucket uses SSE-KMS with a customer-managed KMS key. |
| GAP-02 | 164.312(a)(2)(iv) | DynamoDB intake table uses a customer-managed KMS key. |
| GAP-03 | 164.312(e)(1) | S3 uploads bucket denies non-TLS requests using `aws:SecureTransport=false`. |
| GAP-04 | 164.308(a)(7) | S3 uploads bucket has versioning enabled for recoverability. |
| GAP-05 | 164.312(e)(1) | Lambda runs in the starter VPC private subnets with S3/DynamoDB gateway endpoints. |
| GAP-06 | 164.312(b) | Lambda uses reserved concurrency, DLQ, and X-Ray tracing. |
| GAP-07 | 164.312(a)(1) | Lambda IAM policy removes `dynamodb:*` and `s3:*` in favor of least-privilege actions. |

GAP-08 was deferred. API Gateway logging, throttling, and WAF are reasonable next-sprint controls, but this submission prioritizes the most material PHI storage, access, encryption, and evidence-chain gaps.

## Policy suite

The `policies/` directory contains seven HIPAA-mapped Rego policies, each with its own `_test.rego` file. The policies check the Terraform plan for the remediations above and cite HIPAA control IDs in developer-facing deny messages. `opa test ./policies` must pass before Conftest evaluates the plan.

## Evidence pipeline

The GitHub Actions workflow runs on pull requests, pushes to `main`, and manual dispatch. It performs Terraform plan, OPA/Conftest policy evaluation, optional tfsec evidence capture, apply on merge to `main`, Cosign keyless signing, and upload of the evidence bundle to the Object Lock vault. The evidence bundle includes `plan.json`, `plan.txt`, `opa-results.json`, `opa-test.txt`, `tfsec.sarif`, apply/state context, commit metadata, SHA-256 hash, Sigstore bundle, and upload receipt.

Failed policy gates still produce signed evidence. This preserves negative evidence and demonstrates the control failure rather than losing it when the job exits.

## OSCAL traceability

`oscal/components/acme-health-intake-component-definition.json` describes the governed starter workload and maps implementation statements to the Terraform resources that enforce them. Evidence links point to signed S3 objects in the evidence vault. Because HIPAA does not have an official NIST OSCAL catalog, the component references NIST SP 800-66 Rev. 2 and carries HIPAA Security Rule section IDs as control identifiers.

## Trade-offs

The GitHub OIDC role uses broad permissions inside a single-purpose sandbox so the capstone can run end-to-end without IAM policy debugging becoming the project. The role trust policy is still constrained to this repository. In production, I would replace that broad role with a least-privilege deployment role and separate the evidence vault into its own AWS account.

I used S3/DynamoDB gateway endpoints rather than a NAT Gateway to keep the VPC Lambda functional without adding unnecessary recurring cost. I used Object Lock `GOVERNANCE` mode with one-day retention to demonstrate preservation while retaining cleanup ability.

## What I would do with another sprint

I would close GAP-08 by adding API Gateway access logs, throttling, and a WAFv2 Web ACL with a minimal managed-rule baseline. I would also split the GitHub Actions role into plan-only and apply roles, move the evidence vault to a separate account, add AWS Config detective controls, and publish a stricter OSCAL profile using a stable catalog source.

## What I did not get to

I did not implement WAF, AWS Config, Security Hub, a separate evidence-vault account, or a production-grade least-privilege GitHub deployment role. Those are intentionally deferred to keep the capstone small, integrated, and verifiable.
MD

cat > README.md <<'MD'
# CGE-P Capstone — Acme Health Patient Intake API

This repo is a governed fork/derivative of `GRCEngClub/cgep-app-starter`. It wraps the inherited Patient Intake API with a HIPAA-oriented GRC engineering baseline: Terraform controls, Rego policy gates, GitHub Actions evidence generation, Cosign signing, S3 Object Lock preservation, and OSCAL traceability.

## Quick verification

```bash
opa test ./policies
cd terraform
terraform init
terraform validate
terraform plan -out=tfplan
terraform show -json tfplan > ../evidence/plan.json
cd ..
conftest test --policy policies evidence/plan.json
```

## Evidence verification

Replace the values below with the submitted run ID and vault name.

```bash
EVIDENCE_VAULT=<vault-name> bash scripts/verify-evidence.sh <run-id> --profile <aws-profile>
```

Expected final line:

```text
CHAIN INTACT for run <run-id>
```

## OSCAL validation

```bash
pip install compliance-trestle
trestle validate -f oscal/components/acme-health-intake-component-definition.json
trestle validate -f oscal/profiles/hipaa-minimum-profile.json
```

## Scope

Primary framework: HIPAA Security Rule.

Closed gaps: GAP-01, GAP-02, GAP-03, GAP-04, GAP-05, GAP-06, GAP-07.

Deferred: GAP-08, documented in `WRITEUP.md`.
MD

terraform fmt -recursive terraform oidc >/dev/null || true

echo "CGE-P capstone scaffold generated. Next: run terraform fmt/validate/plan, then follow the rapid runbook."
