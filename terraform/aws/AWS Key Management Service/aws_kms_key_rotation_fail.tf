provider "aws" {
  region = "us-west-2"
}

resource "aws_kms_key" "example" {
  description             = "An example symmetric encryption KMS key"
  enable_key_rotation     = false
}
