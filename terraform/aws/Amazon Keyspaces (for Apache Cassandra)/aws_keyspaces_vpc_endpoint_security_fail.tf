provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "example_vpc_fail" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_vpc_endpoint" "example_endpoint_fail" {
  vpc_id = aws_vpc.example_vpc_fail.id
  service_name = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Interface"
}

resource "aws_keyspaces_keyspace" "example_keyspace_fail" {
  name = "example_fail_keyspace"
}
