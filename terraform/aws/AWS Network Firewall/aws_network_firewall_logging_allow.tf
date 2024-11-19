# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create Network Firewall with proper configuration
resource "aws_networkfirewall_firewall" "pass_firewall" {
  name   = "pass-firewall"
  vpc_id = "vpc-12345678"

  firewall_policy_arn = "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example"

  subnet_mapping {
    subnet_id = "subnet-12345678"
  }

  tags = {
    Environment = "production"
  }
}

# Configure logging for the firewall with both ALERT and FLOW types
resource "aws_networkfirewall_logging_configuration" "pass_logging" {
  firewall_arn = aws_networkfirewall_firewall.pass_firewall.arn

  logging_configuration {
    log_destination_config {
      log_destination = {
        logGroup = "/aws/network-firewall/alerts"
      }
      log_destination_type = "CloudWatchLogs"
      log_type             = "ALERT"
    }

    log_destination_config {
      log_destination = {
        bucketName = "network-firewall-logs"
        prefix     = "flow-logs"
      }
      log_destination_type = "S3"
      log_type             = "FLOW"
    }
  }
}
