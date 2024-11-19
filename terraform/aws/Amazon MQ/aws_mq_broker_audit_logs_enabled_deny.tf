provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_mq_broker" "fail_broker" {
  provider = aws.fail_aws
  broker_name = "fail-broker"
  engine_type = "ActiveMQ"
  engine_version = "5.15.0"
  host_instance_type = "mq.t2.micro"

  user {
    username = "example"
    password = "example123"
  }

  logs {
    general = true
    audit = false
  }
}
