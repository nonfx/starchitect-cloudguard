resource "aws_api_gateway_rest_api" "example_api_pass" {
  name        = "example-api-pass"
  description = "Example API with X-Ray"
}

resource "aws_api_gateway_stage" "example_stage_pass" {
  stage_name         = "prod"
  rest_api_id        = aws_api_gateway_rest_api.example_api_pass.id
  deployment_id      = aws_api_gateway_deployment.example_deployment_pass.id
  xray_tracing_enabled = true
}

resource "aws_api_gateway_deployment" "example_deployment_pass" {
  rest_api_id = aws_api_gateway_rest_api.example_api_pass.id
}
