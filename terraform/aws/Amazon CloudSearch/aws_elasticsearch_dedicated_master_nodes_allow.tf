provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_elasticsearch_domain" "pass_domain" {
  provider = aws.pass_aws
  domain_name = "pass-es-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
    instance_count = 3
    
    # Properly configured with 3 dedicated master nodes
    dedicated_master_enabled = true
    dedicated_master_count = 3
    dedicated_master_type = "t3.small.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  tags = {
    Environment = "production"
    Purpose = "search"
  }
}