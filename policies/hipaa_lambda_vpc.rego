package cgep.hipaa.lambda_vpc

# METADATA
# title: GAP-05 — Lambda must run inside the starter VPC
# custom:
#   framework: hipaa
#   controls:
#     - "164.312(e)(1)"
#   severity: medium
#   remediation: Add vpc_config to aws_lambda_function.intake referencing starter private subnets and a hardened security group.

resource contains r if { r := input.planned_values.root_module.resources[_] }

lambda_has_vpc_config if {
  resource[r]
  r.type == "aws_lambda_function"
  r.name == "intake"
  vpc := r.values.vpc_config[_]
  count(vpc.subnet_ids) > 0
  count(vpc.security_group_ids) > 0
}

deny contains msg if {
  not lambda_has_vpc_config
  msg := "HIPAA 164.312(e)(1) / GAP-05: intake Lambda must run inside the starter VPC private subnets."
}
