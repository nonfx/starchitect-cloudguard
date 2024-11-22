resource "aws_cloudwatch_log_group" "fail" {
  name              = "/aws/lambda/fail-function"
}
