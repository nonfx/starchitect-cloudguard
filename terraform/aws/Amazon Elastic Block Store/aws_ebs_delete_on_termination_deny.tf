provider "aws" {
  region = "us-west-2"
}

resource "aws_instance" "failing_example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  root_block_device {
    volume_type = "gp2"
    volume_size = 8
    delete_on_termination = false
  }

  ebs_block_device {
    device_name = "/dev/sdf"
    volume_type = "gp2"
    volume_size = 10
    delete_on_termination = false
  }

  tags = {
    Name = "failing_example"
  }
}
