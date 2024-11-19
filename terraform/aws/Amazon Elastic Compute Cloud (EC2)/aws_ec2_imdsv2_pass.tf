provider "aws" {
  region = "us-west-2"
}

resource "aws_instance" "example" {
  metadata_options {
    http_endpoint = "enabled"
    http_tokens = "required"
  }
}


