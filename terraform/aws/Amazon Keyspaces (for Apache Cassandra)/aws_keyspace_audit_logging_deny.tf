provider "aws" {
  region = "us-east-1"
}

resource "aws_keyspaces_keyspace" "example_fail" {
  name = "example-keyspace-fail"
}

