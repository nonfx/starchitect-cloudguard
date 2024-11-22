provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create enabled GuardDuty detector
resource "aws_guardduty_detector" "pass" {
  provider = aws.pass_aws
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = {
    Environment = "production"
  }
}
