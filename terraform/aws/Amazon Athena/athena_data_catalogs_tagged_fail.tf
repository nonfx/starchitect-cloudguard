resource "aws_athena_data_catalog" "example_fail" {
  name        = "example-catalog-fail"
  description = "Example Athena Data Catalog without tags"
  type        = "LAMBDA"

  parameters = {
    "function" = "arn:aws:lambda:us-west-2:123456789012:function:example-lambda"
  }
}
