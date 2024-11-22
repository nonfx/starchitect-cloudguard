# Compliant Redshift parameter group configuration
provider "aws" {
  region = "us-west-2"
}

resource "aws_redshift_parameter_group" "pass_example" {
  name   = "redshift-parameter-group-pass"
  family = "redshift-1.0"

  parameter {
    name  = "require_ssl"
    value = "true"  # Compliant: SSL required
  }

  parameter {
    name  = "enable_user_activity_logging"
    value = "true"
  }

  tags = {
    Environment = "production"
    Security   = "high"
  }
}
