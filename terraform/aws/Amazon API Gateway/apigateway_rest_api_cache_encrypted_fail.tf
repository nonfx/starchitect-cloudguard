resource "aws_api_gateway_rest_api" "example" {
  name        = "example-api"
  description = "Example REST API"
}

resource "aws_api_gateway_stage" "example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "example"

  cache_cluster_enabled = true
  cache_cluster_size    = 0.5
  # cache_data_encrypted is not set, which defaults to false
}

resource "aws_api_gateway_deployment" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_method_settings" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "*/*"

  # settings missing
}
