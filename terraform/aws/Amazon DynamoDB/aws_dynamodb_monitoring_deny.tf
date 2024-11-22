provider "aws" {
  region = "us-west-2"
}

resource "aws_dynamodb_table" "example_table" {
  name           = "example-table"
  billing_mode   = "PROVISIONED"
  read_capacity  = 10
  write_capacity = 10
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_cloudwatch_metric_alarm" "example_alarm" {
  alarm_name                = "example-alarm"
  namespace                 = "AWS/DynamoDB"
  metric_name               = "SuccessfulRequestLatency"
  statistic                 = "Average"
  period                    = 300
  evaluation_periods        = 1
  threshold                 = 300
  comparison_operator       = "GreaterThanThreshold"
  dimensions = {
    TableName = aws_dynamodb_table.example_table.name
  }
}
