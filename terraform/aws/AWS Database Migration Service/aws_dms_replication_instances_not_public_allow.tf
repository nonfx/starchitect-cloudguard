provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_dms_replication_instance" "pass_test" {
  provider = aws.pass_aws

  replication_instance_id = "pass-dms-replication-instance"
  replication_instance_class = "dms.t2.micro"
  allocated_storage = 20

  # This keeps the instance private
  publicly_accessible = false

  vpc_security_group_ids = ["sg-12345678"]

  tags = {
    Name = "pass-test"
    Environment = "production"
  }
}
