provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create Elasticsearch domain with sufficient nodes
resource "aws_elasticsearch_domain" "pass_example" {
  provider = aws.pass_aws
  domain_name = "pass-es-domain"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
    instance_count = 3
    zone_awareness_enabled = true
    
    zone_awareness_config {
      availability_zone_count = 3
    }
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
  }

  tags = {
    Environment = "production"
  }
}