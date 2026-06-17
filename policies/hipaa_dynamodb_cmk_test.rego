package cgep.hipaa.dynamodb_cmk

import rego.v1

test_pass_dynamodb_cmk if {
  count(deny) == 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_dynamodb_table","name":"intake","values":{"server_side_encryption":[{"enabled":true,"kms_key_arn":"arn:aws:kms:us-east-1:111122223333:key/example"}]}}]}}}
}

test_fail_dynamodb_no_cmk if {
  count(deny) > 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_dynamodb_table","name":"intake","values":{}}]}}}
}
