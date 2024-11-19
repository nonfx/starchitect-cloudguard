resource "aws_cloudwatch_metric_alarm" "pass" {
  alarm_name                = "pass-alarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "2"
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "80"
  alarm_description         = "This metric monitors ec2 cpu utilization"
  insufficient_data_actions = []
  actions_enabled           = true
  alarm_actions             = ["arn:aws:sns:us-east-1:123456789012:my-topic"]
}
