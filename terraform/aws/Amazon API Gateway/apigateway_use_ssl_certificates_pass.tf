resource "aws_api_gateway_rest_api" "example_api_pass" {
  name        = "example-api-pass"
  description = "Example API with SSL"
}

resource "aws_api_gateway_stage" "example_stage_pass" {
  stage_name         = "prod"
  rest_api_id        = aws_api_gateway_rest_api.example_api_pass.id
  deployment_id      = aws_api_gateway_deployment.example_deployment_pass.id
  client_certificate_id = aws_api_gateway_client_certificate.example_certificate.id
}

resource "aws_api_gateway_deployment" "example_deployment_pass" {
  rest_api_id = aws_api_gateway_rest_api.example_api_pass.id
}

resource "aws_api_gateway_client_certificate" "example_certificate" {
  description = "SSL Certificate for backend authentication"
}
