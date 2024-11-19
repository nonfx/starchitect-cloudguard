provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_sagemaker_endpoint_configuration" "fail_config" {
  provider = aws.fail_aws
  name = "fail-endpoint-config"

  production_variants {
    variant_name           = "variant-1"
    model_name            = "example-model"
    initial_instance_count = 1  # This fails because only one instance is specified
    instance_type         = "ml.t2.medium"
  }

  tags = {
    Environment = "Test"
  }
}