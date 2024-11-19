provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias  = "us-west-2"
  region = "us-west-2"
}

provider "aws" {
  alias  = "eu-central-1"
  region = "eu-central-1"
}

# Create an IAM Role for EC2 instances
resource "aws_iam_role" "ec2_role" {
  name = "EC2InstanceRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# IAM Access Analyzer for us-east-1 region
resource "aws_accessanalyzer_analyzer" "example_us_east_1" {
  analyzer_name     = "example-analyzer-us-east-1"
  type              = "ACCOUNT"
}

# IAM Access Analyzer for us-west-2 region
resource "aws_accessanalyzer_analyzer" "example_us_west_2" {
  analyzer_name     = "example-analyzer-us-west-2"
  type              = "ACCOUNT"
}

# IAM Access Analyzer for eu-central-1 region
resource "aws_accessanalyzer_analyzer" "example_eu_central_1" {
  analyzer_name     = "example-analyzer-eu-central-1"
  type              = "ACCOUNT"
}
