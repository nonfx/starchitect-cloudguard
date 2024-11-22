provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "example_vpc_pass" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_vpc_endpoint" "example_endpoint_pass" {
  vpc_id = aws_vpc.example_vpc_pass.id
  service_name = "cassandra.amazonaws.com"
  vpc_endpoint_type = "Interface"
}

resource "aws_keyspaces_keyspace" "example_keyspace_pass" {
  name = "example_pass_keyspace"
}
