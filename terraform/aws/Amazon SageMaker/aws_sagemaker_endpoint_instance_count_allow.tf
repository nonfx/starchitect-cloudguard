provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_sagemaker_endpoint_configuration" "pass_config" {
  provider = aws.pass_aws
  name = "pass-endpoint-config"

  production_variants {
    variant_name           = "variant-1"
    model_name            = "example-model"
    initial_instance_count = 2  # This passes because it has multiple instances for high availability
    instance_type         = "ml.t2.medium"
  }

  tags = {
    Environment = "Production"
    HighAvailability = "Enabled"
  }
}