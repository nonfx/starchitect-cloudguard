resource "aws_appsync_graphql_api" "example" {
  name = "example-api"
  authentication_type = "API_KEY"

  log_config {
    field_log_level = "NONE"
    cloudwatch_logs_role_arn = aws_iam_role.example.arn
  }
}

resource "aws_iam_role" "example" {
  name = "example-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Principal = {
        Service = "appsync.amazonaws.com"
      },
      Effect = "Allow",
      Sid = ""
    }]
  })
}
