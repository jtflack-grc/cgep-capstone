package cgep.hipaa.lambda_vpc

import rego.v1

test_pass_lambda_vpc if {
  count(deny) == 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_lambda_function","name":"intake","values":{"vpc_config":[{"subnet_ids":["subnet-1"],"security_group_ids":["sg-1"]}]}}]}}}
}

test_fail_lambda_no_vpc if {
  count(deny) > 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_lambda_function","name":"intake","values":{}}]}}}
}
