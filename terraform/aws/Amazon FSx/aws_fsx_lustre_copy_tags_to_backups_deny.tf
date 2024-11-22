provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create FSx Lustre file system without copy tags to backups
resource "aws_fsx_lustre_file_system" "fail_system" {
  provider = aws.fail_aws
  storage_capacity = 1200
  subnet_ids = ["subnet-12345678"]
  deployment_type = "PERSISTENT_1"
  per_unit_storage_throughput = 50
  
  tags = {
    Environment = "test"
    Name = "fail-lustre-system"
  }
  
  # copy_tags_to_backups not set (defaults to false)
}
