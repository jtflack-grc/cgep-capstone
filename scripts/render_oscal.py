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
