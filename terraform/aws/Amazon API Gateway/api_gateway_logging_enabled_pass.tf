# Create an API Gateway REST API
resource "aws_api_gateway_rest_api" "example" {
  name = "example-api"
}

# Create an API Gateway deployment
resource "aws_api_gateway_deployment" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = "test"
}

# Create a CloudWatch log group for access logs
resource "aws_cloudwatch_log_group" "access_logs" {
  name = "example-api-access-logs"
}

# Create an IAM role for API Gateway to write logs to CloudWatch
resource "aws_iam_role" "api_gateway_cloudwatch" {
  name = "api-gateway-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "apigateway.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "api_gateway_cloudwatch" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs"
  role       = aws_iam_role.api_gateway_cloudwatch.name
}

# Configure API Gateway stage with logging settings
resource "aws_api_gateway_stage" "example" {
  deployment_id = aws_api_gateway_deployment.example.id
  rest_api_id   = aws_api_gateway_rest_api.example.id
  stage_name    = "test"

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access_logs.arn
    format          = "$context.extendedRequestId $context.identity.sourceIp $context.identity.caller $context.identity.user [$context.requestTime] \"$context.httpMethod $context.resourcePath $context.protocol\" $context.status $context.responseLength $context.requestId"
  }

  depends_on = [aws_iam_role_policy_attachment.api_gateway_cloudwatch]
}

# Configure API Gateway method settings for logging
resource "aws_api_gateway_method_settings" "example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled = true
    logging_level   = "ERROR"
  }
}
