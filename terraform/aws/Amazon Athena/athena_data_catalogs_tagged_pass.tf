resource "aws_athena_data_catalog" "example_pass" {
  name        = "example-catalog-pass"
  description = "Example Athena Data Catalog with tags"
  type        = "LAMBDA"

  parameters = {
    "function" = "arn:aws:lambda:us-west-2:123456789012:function:example-lambda"
  }

  tags = {
    Environment = "Production"
    Project     = "DataAnalytics"
  }
}
