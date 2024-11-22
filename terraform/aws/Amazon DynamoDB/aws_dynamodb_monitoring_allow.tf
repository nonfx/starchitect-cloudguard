provider "aws" {
  region = "us-west-2"
}

# DynamoDB Table
resource "aws_dynamodb_table" "example_table" {
  name           = "example-table"
  hash_key       = "id"
  billing_mode   = "PAY_PER_REQUEST"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name = "example-table"
  }
}

# CloudWatch Alarm for User Errors
resource "aws_cloudwatch_metric_alarm" "user_errors" {
  alarm_name                = "DynamoDBUserErrorsAlarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "UserErrors"
  namespace                 = "AWS/DynamoDB"
  period                    = "60"
  statistic                 = "Sum"
  threshold                 = "1"

  dimensions = {
    TableName = aws_dynamodb_table.example_table.name
  }

  alarm_description = "This alarm monitors any user errors, such as invalid requests or permissions issues."
  actions_enabled   = false

  tags = {
    Name = "DynamoDBUserErrorsAlarm"
  }
}

# CloudWatch Alarm for System Errors
resource "aws_cloudwatch_metric_alarm" "system_errors" {
  alarm_name                = "DynamoDBSystemErrorsAlarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "SystemErrors"
  namespace                 = "AWS/DynamoDB"
  period                    = "60"
  statistic                 = "Sum"
  threshold                 = "1"

  dimensions = {
    TableName = aws_dynamodb_table.example_table.name
  }

  alarm_description = "This alarm monitors any system errors within DynamoDB, such as internal failures."
  actions_enabled   = false

  tags = {
    Name = "DynamoDBSystemErrorsAlarm"
  }
}

# CloudWatch Alarm for Throttled Requests
resource "aws_cloudwatch_metric_alarm" "throttled_requests" {
  alarm_name                = "DynamoDBThrottledRequestsAlarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "ThrottledRequests"
  namespace                 = "AWS/DynamoDB"
  period                    = "60"
  statistic                 = "Sum"
  threshold                 = "1"

  dimensions = {
    TableName = aws_dynamodb_table.example_table.name
  }

  alarm_description = "This alarm monitors any throttled requests, indicating that the table is exceeding its provisioned throughput."
  actions_enabled   = false

  tags = {
    Name = "DynamoDBThrottledRequestsAlarm"
  }
}

# CloudWatch Alarm for High Read Capacity Usage
resource "aws_cloudwatch_metric_alarm" "high_read_capacity" {
  alarm_name                = "DynamoDBHighReadCapacityAlarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "ConsumedReadCapacityUnits"
  namespace                 = "AWS/DynamoDB"
  period                    = "60"
  statistic                 = "Sum"
  threshold                 = "1000"

  dimensions = {
    TableName = aws_dynamodb_table.example_table.name
  }

  alarm_description = "This alarm monitors if the read capacity exceeds 1000 units in a 1-minute period."
  actions_enabled   = false

  tags = {
    Name = "DynamoDBHighReadCapacityAlarm"
  }
}

# CloudWatch Alarm for High Write Capacity Usage
resource "aws_cloudwatch_metric_alarm" "high_write_capacity" {
  alarm_name                = "DynamoDBHighWriteCapacityAlarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "ConsumedWriteCapacityUnits"
  namespace                 = "AWS/DynamoDB"
  period                    = "60"
  statistic                 = "Sum"
  threshold                 = "500"

  dimensions = {
    TableName = aws_dynamodb_table.example_table.name
  }

  alarm_description = "This alarm monitors if the write capacity exceeds 500 units in a 1-minute period."
  actions_enabled   = false

  tags = {
    Name = "DynamoDBHighWriteCapacityAlarm"
  }
}

# CloudWatch Dashboard for DynamoDB Monitoring
resource "aws_cloudwatch_dashboard" "dynamodb_dashboard" {
  dashboard_name = "DynamoDBDashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric",
        x = 0,
        y = 0,
        width = 24,
        height = 6,
        properties = {
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", "TableName", aws_dynamodb_table.example_table.name],
            ["AWS/DynamoDB", "ConsumedWriteCapacityUnits", "TableName", aws_dynamodb_table.example_table.name],
            ["AWS/DynamoDB", "ThrottledRequests", "TableName", aws_dynamodb_table.example_table.name],
            ["AWS/DynamoDB", "UserErrors", "TableName", aws_dynamodb_table.example_table.name],
            ["AWS/DynamoDB", "SystemErrors", "TableName", aws_dynamodb_table.example_table.name]
          ],
          period = 300,
          stat = "Sum",
          region = "us-west-2",
          title = "DynamoDB Metrics"
        }
      }
    ]
  })
}
