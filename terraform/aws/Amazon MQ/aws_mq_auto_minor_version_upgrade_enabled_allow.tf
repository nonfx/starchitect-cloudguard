provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_mq_broker" "pass_broker" {
  provider = aws.pass_aws
  broker_name = "pass-broker"
  engine_type = "ActiveMQ"
  engine_version = "5.15.0"
  host_instance_type = "mq.t2.micro"
  auto_minor_version_upgrade = true

  user {
    username = "example"
    password = "example123"
  }
}
