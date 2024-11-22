# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create a Glue job with logging enabled - this will pass the policy check
resource "aws_glue_job" "pass_example" {
  name     = "pass-example-job"
  role_arn = "arn:aws:iam::123456789012:role/service-role/AWSGlueServiceRole"

  command {
    script_location = "s3://aws-glue-scripts/example-script.py"
    python_version  = "3"
  }

  # Default arguments with logging enabled
  default_arguments = {
    "--job-language" = "python"
    "--enable-continuous-cloudwatch-log" = "true"
    "--enable-metrics" = "true"
    "--extra-py-files" = "s3://aws-glue-scripts/libraries/custom-library.py"
  }

  max_retries = 1
  timeout     = 2880

  execution_property {
    max_concurrent_runs = 1
  }

  tags = {
    Environment = "production"
    Owner       = "data-team"
  }
}
