provider "aws" {
  region = "us-west-2"
}

resource "aws_qldb_ledger" "fail-ledger" {
  name             = "fail-ledger"
  permissions_mode = "STANDARD"
}

resource "aws_cloudwatch_metric_alarm" "example_fail" {
  alarm_name                = "example-fail-alarm"
  comparison_operator       = "GreaterThanThreshold"
  evaluation_periods        = "1"
  metric_name               = "JournalStorage"
  namespace                 = "AWS/QLDB"
  period                    = "300"
  statistic                 = "Average"
  threshold                 = "20000"
  alarm_description         = "This alarm monitors QLDB JournalStorage metric without LedgerName dimension"
  actions_enabled           = true
  alarm_actions             = ["arn:aws:sns:us-west-2:123456789012:example-topic"]
  ok_actions                = ["arn:aws:sns:us-west-2:123456789012:example-topic"]
  insufficient_data_actions = []
}
