provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_fsx_openzfs_file_system" "fail_example" {
  provider = aws.fail_aws
  storage_capacity    = 64
  subnet_ids          = ["subnet-1234567890abcdef0"]
  deployment_type     = "SINGLE_AZ_1"
  throughput_capacity = 64
  
  # Tag copying not enabled for backups and volumes
  copy_tags_to_backups = false
  copy_tags_to_volumes = false

  tags = {
    Name = "fail-example"
    Environment = "test"
  }
}
