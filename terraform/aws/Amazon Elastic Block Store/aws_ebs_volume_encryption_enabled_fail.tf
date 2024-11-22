provider "aws" {
  region = "us-west-2"
}



# Enable default EBS encryption for the region
resource "aws_ebs_encryption_by_default" "examplef" {
  enabled = false
}

resource "aws_ebs_volume" "example" {
  availability_zone = "us-west-2a"
  size              = 1

  tags = {
    Name = "example-ebs-volume"
  }

  depends_on = [aws_ebs_encryption_by_default.examplef]
}
