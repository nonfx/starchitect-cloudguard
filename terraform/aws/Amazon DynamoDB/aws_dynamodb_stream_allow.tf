provider "aws" {
  region = "us-west-2"
}

# Create the DynamoDB table with Streams enabled
resource "aws_dynamodb_table" "example_table" {
  name           = "example-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  stream_enabled = true
  stream_view_type = "NEW_IMAGE"  # Capture only the new image of the item

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "example-table"
    Environment = "Production"
  }
}

# Create the IAM role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "lambda-dynamodb-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "sts:AssumeRole",
        Effect    = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Attach necessary policies to the IAM role
resource "aws_iam_role_policy" "lambda_policy" {
  name   = "lambda-dynamodb-policy"
  role   = aws_iam_role.lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "dynamodb:GetRecords",
          "dynamodb:GetShardIterator",
          "dynamodb:DescribeStream",
          "dynamodb:ListStreams"
        ],
        Effect   = "Allow",
        Resource = "*"
      },
      {
        Action = "logs:*",
        Effect = "Allow",
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# Create the Lambda function
resource "aws_lambda_function" "compliance_checker" {
  function_name = "compliance_checker"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.9"

  filename = "lambda_function.zip"  # Zip file containing your Lambda code

  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.example_table.name
    }
  }

  depends_on = [aws_iam_role_policy.lambda_policy]
}

# Create the event source mapping between DynamoDB Streams and Lambda
resource "aws_lambda_event_source_mapping" "dynamodb_stream_to_lambda" {
  event_source_arn = aws_dynamodb_table.example_table.stream_arn
  function_name    = aws_lambda_function.compliance_checker.arn
  starting_position = "LATEST"
}

# (Optional) Create a CloudWatch log group for Lambda
resource "aws_cloudwatch_log_group" "lambda_log_group" {
  name              = "/aws/lambda/compliance_checker"
  retention_in_days = 14
}
