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
