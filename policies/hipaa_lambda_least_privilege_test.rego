package cgep.hipaa.lambda_least_privilege

import rego.v1

test_pass_least_privilege if {
  count(deny) == 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_iam_role_policy","name":"lambda_inline","values":{"policy":"{\"Action\":[\"dynamodb:PutItem\",\"s3:PutObject\"]}"}}]}}}
}

test_fail_wildcard_privileges if {
  count(deny) > 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_iam_role_policy","name":"lambda_inline","values":{"policy":"{\"Action\":[\"dynamodb:*\",\"s3:*\"]}"}}]}}}
}
