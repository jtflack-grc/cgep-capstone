package cgep.hipaa.lambda_resilience

test_pass_lambda_resilience if {
  count(deny) == 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_lambda_function","name":"intake","values":{"reserved_concurrent_executions":10,"dead_letter_config":[{"target_arn":"arn:aws:sqs:us-east-1:111122223333:q"}],"tracing_config":[{"mode":"Active"}]}}]}}}
}

test_fail_lambda_no_resilience if {
  count(deny) > 0 with input as {"planned_values":{"root_module":{"resources":[{"type":"aws_lambda_function","name":"intake","values":{"reserved_concurrent_executions":-1}}]}}}
}
