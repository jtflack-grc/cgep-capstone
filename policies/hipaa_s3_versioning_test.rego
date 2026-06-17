package cgep.hipaa.s3_versioning

import rego.v1

test_pass_versioning if {
  count(deny) == 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_s3_bucket_versioning","name":"uploads","values":{"versioning_configuration":[{"status":"Enabled"}]}}]}}}
}

test_fail_no_versioning if {
  count(deny) > 0 with input as {"planned_values":{"root_module":{"resources":[]}}}
}
