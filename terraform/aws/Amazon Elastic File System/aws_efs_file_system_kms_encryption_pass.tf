provider "aws" {
  region = "us-west-2"
}

resource "aws_efs_file_system" "example" {
  name = "example-aggregator"
  encrypted = true
  kms_key_id = "a"
}
