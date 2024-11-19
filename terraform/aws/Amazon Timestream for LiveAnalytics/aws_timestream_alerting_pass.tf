resource "aws_timestreamwrite_database" "example" {
  database_name = "example-timestream-db"
}

resource "aws_timestreamwrite_table" "example_table" {
  database_name = aws_timestreamwrite_database.example.database_name
  table_name    = "example-table"
  retention_properties {
    memory_store_retention_period_in_hours = 24
    magnetic_store_retention_period_in_days = 7
  }
}

resource "aws_cloudwatch_metric_alarm" "high_write_records" {
  alarm_name                = "high-write-records"
  comparison_operator       = "GreaterThanThreshold"
  evaluation_periods        = 1
  metric_name              = "WriteRecords.Bytes"
  namespace                 = "AWS/Timestream"
  period                    = 300
  statistic                 = "Sum"
  threshold                 = 1000000
  alarm_description         = "This metric monitors high write records to Timestream"
  actions_enabled          = true
  alarm_actions            = ["arn:aws:sns:us-west-2:123456789012:NotifyMe"]
  ok_actions               = ["arn:aws:sns:us-west-2:123456789012:NotifyMe"]
  insufficient_data_actions = ["arn:aws:sns:us-west-2:123456789012:NotifyMe"]
}
