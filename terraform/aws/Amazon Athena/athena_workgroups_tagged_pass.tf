resource "aws_athena_workgroup" "example_pass" {
  name = "example-athena-workgroup"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://my-athena-query-results/"
    }
  }

  tags = {
    Environment = "Production"
    Project     = "DataAnalytics"
  }
}
