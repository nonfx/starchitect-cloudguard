resource "aws_api_gateway_rest_api" "example_api_pass" {
  name        = "example-api-pass"
  description = "Example API with WAF ACL"
}

resource "aws_api_gateway_stage" "example_stage_pass" {
  stage_name         = "prod"
  rest_api_id        = aws_api_gateway_rest_api.example_api_pass.id
  deployment_id      = aws_api_gateway_deployment.example_deployment_pass.id
  web_acl_arn        = aws_waf_web_acl.example_acl.arn
}

resource "aws_api_gateway_deployment" "example_deployment_pass" {
  rest_api_id = aws_api_gateway_rest_api.example_api_pass.id
}

resource "aws_waf_web_acl" "example_acl" {
  name        = "example-acl"
  metric_name = "ExampleMetric"

  default_action {
    type = "ALLOW"
  }
}
