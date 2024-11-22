provider "aws" {
  region = "us-west-2"
}

resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-test-bucket"
}

resource "aws_iam_user" "user" {
  name = "my-mfa-user"
}

resource "aws_iam_user_mfa_device" "mfa_device" {
  user     = aws_iam_user.user.name
  serial   = "arn:aws:iam::123456789012:mfa/${aws_iam_user.user.name}"
  otp_seed = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.my_bucket.id

  versioning_configuration {
    status = "Enabled"
    mfa_delete = "Enabled"
  }
}

output "bucket_name" {
  value = aws_s3_bucket.my_bucket.bucket
}

output "mfa_arn" {
  value = aws_iam_user_mfa_device.mfa_device.serial
}
