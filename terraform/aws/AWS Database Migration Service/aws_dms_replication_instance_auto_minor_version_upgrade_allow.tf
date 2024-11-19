provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_dms_replication_instance" "pass_test" {
  provider = aws.pass_aws
  replication_instance_id = "pass-test-dms-replication-instance"
  replication_instance_class = "dms.t2.micro"
  
  # Automatic minor version upgrade enabled
  auto_minor_version_upgrade = true
  
  allocated_storage = 20
  
  # Required for replication instance
  vpc_security_group_ids = ["sg-12345678"]
  availability_zone = "us-west-2a"
  
  tags = {
    Environment = "production"
    Name = "pass-test-dms-replication-instance"
  }
}
