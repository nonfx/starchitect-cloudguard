# Non-compliant Redshift parameter group configuration
provider "aws" {
  region = "us-west-2"
}

resource "aws_redshift_parameter_group" "fail_example" {
  name   = "redshift-parameter-group-fail"
  family = "redshift-1.0"

  parameter {
    name  = "require_ssl"
    value = "false"  # Non-compliant: SSL not required
  }

  parameter {
    name  = "enable_user_activity_logging"
    value = "true"
  }
}
