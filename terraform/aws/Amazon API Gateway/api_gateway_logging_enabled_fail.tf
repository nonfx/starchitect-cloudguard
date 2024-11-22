# Create an API Gateway REST API
resource "aws_api_gateway_rest_api" "example" {
  name = "example-api"
}

# Create an API Gateway deployment
resource "aws_api_gateway_deployment" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = "test"
}

# Configure API Gateway stage without logging settings
resource "aws_api_gateway_stage" "example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "test"
}

# Configure API Gateway method settings without logging
resource "aws_api_gateway_method_settings" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled = true
  }
}
