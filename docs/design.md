# CGE-P Capstone Design Spine

Primary framework: HIPAA Security Rule.

Rationale: Acme Health's Patient Intake API ingests patient submissions and optional attachments, so PHI protection is the most direct compliance objective. SOC 2 and CMMC are valid secondary narratives, but HIPAA is the clearest primary framework for a 30-day GRC engineering sprint.

Region: us-east-1.

Evidence vault: S3 Object Lock in GOVERNANCE mode with 1-day retention for lab cleanup. Production would use COMPLIANCE mode and a longer retention period.

Account model: Single AWS sandbox account. Production would separate workload and evidence-vault accounts.

Pipeline behavior: Plan and policy-check on pull requests; apply on merge to main; sign and upload evidence on every run.

Gaps closed technically: GAP-01, GAP-02, GAP-03, GAP-04, GAP-05, GAP-06, GAP-07.

Gap deferred: GAP-08. API Gateway logging/throttling/WAF is a valid next sprint, but this submission prioritizes PHI encryption, VPC placement, least privilege, recoverability, operational resilience, CloudTrail, and signed immutable evidence.
