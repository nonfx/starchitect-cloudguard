provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_dms_replication_instance" "fail_test" {
  provider = aws.fail_aws
  replication_instance_id = "fail-test-dms-replication-instance"
  replication_instance_class = "dms.t2.micro"
  
  # Automatic minor version upgrade disabled
  auto_minor_version_upgrade = false
  
  allocated_storage = 20
  
  # Required for replication instance
  vpc_security_group_ids = ["sg-12345678"]
  availability_zone = "us-west-2a"
}
