package cgep.hipaa.s3_sse_kms

import rego.v1

test_pass_sse_kms if {
  count(deny) == 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_s3_bucket_server_side_encryption_configuration","name":"uploads","values":{"rule":[{"apply_server_side_encryption_by_default":[{"sse_algorithm":"aws:kms","kms_master_key_id":"arn:aws:kms:us-east-1:111122223333:key/example"}]}]}}]}}}
}

test_fail_missing_sse_kms if {
  count(deny) > 0 with input as {"planned_values":{"root_module":{"resources":[]}}}
}
