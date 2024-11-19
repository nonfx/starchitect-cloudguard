resource "aws_api_gateway_rest_api" "example_api" {
  name        = "example-api"
  description = "Example API"
}

resource "aws_api_gateway_stage" "example_stage" {
  stage_name    = "dev"
  rest_api_id   = aws_api_gateway_rest_api.example_api.id
  deployment_id = aws_api_gateway_deployment.example_deployment.id

  # X-Ray tracing is not enabled
}

resource "aws_api_gateway_deployment" "example_deployment" {
  rest_api_id = aws_api_gateway_rest_api.example_api.id
}
