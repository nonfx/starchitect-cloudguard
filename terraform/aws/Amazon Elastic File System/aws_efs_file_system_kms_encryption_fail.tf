provider "aws" {
  region = "us-west-2"
}

resource "aws_efs_file_system" "example" {
  name = "example-aggregator"
  encrypted = false
}

# resource "aws_efs_file_system" "example" {
#   creation_token = "okay"
# }

# resource "aws_efs_file_system" "example" {
#   creation_token = "okay"
#   encrypted = true
# }

# resource "aws_efs_file_system" "example" {
#   kms_key_id = "s"
# }
