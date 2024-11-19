resource "aws_cloudwatch_log_group" "pass" {
  name              = "/aws/lambda/pass-function"
  retention_in_days = 365
}

# -------------------------------------------------
# logs never expire
# resource "aws_cloudwatch_log_group" "pass" {
#   name              = "/aws/lambda/pass-function"
#   retention_in_days = 0
# }
