provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_fsx_openzfs_file_system" "pass_example" {
  provider = aws.pass_aws
  storage_capacity    = 64
  subnet_ids          = ["subnet-1234567890abcdef0"]
  deployment_type     = "SINGLE_AZ_1"
  throughput_capacity = 64
  
  # Tag copying enabled for both backups and volumes
  copy_tags_to_backups = true
  copy_tags_to_volumes = true

  tags = {
    Name = "pass-example"
    Environment = "production"
    Owner = "team-a"
  }
}
