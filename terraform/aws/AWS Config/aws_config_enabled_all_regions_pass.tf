provider "aws" {
  region = "us-west-2"
}

resource "aws_config_configuration_aggregator" "example" {
  name = "example-aggregator"

  account_aggregation_source {
    account_ids = ["123456789012"]
    all_regions = true
  }

  organization_aggregation_source {
    all_regions = true
    role_arn = aws_iam_role.example.arn
  }
}
