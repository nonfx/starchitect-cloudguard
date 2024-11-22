# Example of a compliant Athena workgroup
# CloudWatch metrics logging is enabled with additional security configurations
resource "aws_athena_workgroup" "pass_example" {
  name = "example-workgroup-pass"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true  # Compliant: Metrics logging is enabled

    result_configuration {
      output_location = "s3://my-athena-query-results/"
      
      # Additional security measure: encryption configuration
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }

  tags = {
    Environment = "Production"
    Compliance  = "Enabled"
  }
}