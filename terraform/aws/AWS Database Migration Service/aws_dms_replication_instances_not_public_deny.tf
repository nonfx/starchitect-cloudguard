provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_dms_replication_instance" "fail_test" {
  provider = aws.fail_aws

  replication_instance_id = "fail-dms-replication-instance"
  replication_instance_class = "dms.t2.micro"
  allocated_storage = 20

  # This makes the instance publicly accessible
  publicly_accessible = true

  vpc_security_group_ids = ["sg-12345678"]

  tags = {
    Name = "fail-test"
  }
}
