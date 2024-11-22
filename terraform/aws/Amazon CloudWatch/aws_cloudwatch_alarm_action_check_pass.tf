resource "aws_sns_topic" "alarm" {
  name = "alarm-topic"
}

resource "aws_cloudwatch_metric_alarm" "pass" {
  alarm_name                = "cpu-utilization"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "2"
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "80"
  alarm_description         = "This metric monitors ec2 cpu utilization"
  alarm_actions             = [aws_sns_topic.alarm.arn]
    # These are optional. if not present rule will pass with message
  insufficient_data_actions = [aws_sns_topic.alarm.arn]
  ok_actions                = [aws_sns_topic.alarm.arn]
}
