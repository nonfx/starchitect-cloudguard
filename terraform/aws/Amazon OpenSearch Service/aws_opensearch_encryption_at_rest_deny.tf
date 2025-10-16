# Configure AWS provider for the failing test case
provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create an OpenSearch domain without encryption at rest
resource "aws_opensearch_domain" "fail_domain" {
  provider = aws.fail_aws
  domain_name = "fail-domain"
  
  # Configure basic cluster settings
  cluster_config {
    instance_type = "t3.small.search"
    instance_count = 1
  }

  # Configure EBS storage
  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  # Add tags for resource identification
  tags = {
    Environment = "test"
  }
}
