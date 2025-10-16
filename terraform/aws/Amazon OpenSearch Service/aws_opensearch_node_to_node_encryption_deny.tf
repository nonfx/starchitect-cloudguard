# AWS Provider configuration
provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# OpenSearch domain configuration with node-to-node encryption disabled
resource "aws_opensearch_domain" "fail_test" {
  provider    = aws.fail_aws
  domain_name = "fail-test-domain"

  # Cluster configuration
  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 2
  }

  # Node-to-node encryption explicitly disabled
  node_to_node_encryption {
    enabled = false
  }

  # EBS storage configuration
  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  tags = {
    Environment = "test"
  }
}
