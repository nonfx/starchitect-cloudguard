provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create FSx Lustre file system with copy tags to backups enabled
resource "aws_fsx_lustre_file_system" "pass_system" {
  provider = aws.pass_aws
  storage_capacity = 1200
  subnet_ids = ["subnet-12345678"]
  deployment_type = "PERSISTENT_1"
  per_unit_storage_throughput = 50
  copy_tags_to_backups = true
  
  tags = {
    Environment = "production"
    Name = "pass-lustre-system"
    Owner = "TeamA"
  }
}
