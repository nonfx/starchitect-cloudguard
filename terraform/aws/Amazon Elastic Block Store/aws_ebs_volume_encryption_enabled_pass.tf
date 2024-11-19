provider "aws" {
  region = "us-west-2"
}

# Enable default EBS encryption for the region
resource "aws_ebs_encryption_by_default" "examplep" {
  enabled = true
}

resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  tags = {
    Name = "example-instance"
  }
}

resource "aws_ebs_volume" "example" {
  availability_zone = "us-west-2a"
  size              = 1

  tags = {
    Name = "example-ebs-volume"
  }

  depends_on = [aws_ebs_encryption_by_default.examplep]
}
