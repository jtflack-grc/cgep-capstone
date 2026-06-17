package cgep.hipaa.s3_tls_only

test_pass_tls_deny if {
  count(deny) == 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_s3_bucket_policy","name":"uploads_tls_only","values":{"policy":"{\"Effect\":\"Deny\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}"}}]}}}
}

test_fail_no_tls_deny if {
  count(deny) > 0 with input as {"planned_values":{"root_module":{"resources":[]}}}
}
