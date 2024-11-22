provider "aws" {
  region = "us-west-2"
}

resource "aws_qldb_ledger" "pass-ledger" {
  name             = "pass-ledger"
  permissions_mode = "STANDARD"
}

resource "aws_cloudwatch_metric_alarm" "example_pass" {
  alarm_name                = "example-pass-alarm"
  comparison_operator       = "GreaterThanThreshold"
  evaluation_periods        = "1"
  metric_name               = "JournalStorage"
  namespace                 = "AWS/QLDB"
  period                    = "300"
  statistic                 = "Average"
  threshold                 = "20000"
  alarm_description         = "This alarm monitors QLDB JournalStorage metric for a specific ledger"
  actions_enabled           = true
  alarm_actions             = ["arn:aws:sns:us-west-2:123456789012:example-topic"]
  ok_actions                = ["arn:aws:sns:us-west-2:123456789012:example-topic"]
  insufficient_data_actions = []
  dimensions = {
    "LedgerName" = aws_qldb_ledger.pass-ledger.name
  }
}
