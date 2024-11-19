provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_elasticsearch_domain" "fail_domain" {
  provider = aws.fail_aws
  domain_name = "fail-es-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
    instance_count = 2
    
    # Only 2 dedicated master nodes, which is insufficient
    dedicated_master_enabled = true
    dedicated_master_count = 2
    dedicated_master_type = "t3.small.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }
}