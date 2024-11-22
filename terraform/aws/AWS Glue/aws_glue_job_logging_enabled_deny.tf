# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create a Glue job without logging enabled - this will fail the policy check
resource "aws_glue_job" "fail_example" {
  name     = "fail-example-job"
  role_arn = "arn:aws:iam::123456789012:role/service-role/AWSGlueServiceRole"

  command {
    script_location = "s3://aws-glue-scripts/example-script.py"
    python_version  = "3"
  }

  # Default arguments without logging enabled
  default_arguments = {
    "--job-language" = "python"
    "--extra-py-files" = "s3://aws-glue-scripts/libraries/custom-library.py"
  }

  max_retries = 1
  timeout     = 2880

  execution_property {
    max_concurrent_runs = 1
  }
}
