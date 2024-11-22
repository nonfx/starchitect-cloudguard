# Example of a non-compliant Athena workgroup
# CloudWatch metrics logging is disabled
resource "aws_athena_workgroup" "fail_example" {
  name = "example-workgroup-fail"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false  # Non-compliant: Metrics logging is disabled

    result_configuration {
      output_location = "s3://my-athena-query-results/"
    }
  }

  tags = {
    Environment = "Development"
  }
}