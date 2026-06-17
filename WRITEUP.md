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
