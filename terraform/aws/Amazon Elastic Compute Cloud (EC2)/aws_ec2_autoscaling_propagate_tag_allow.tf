resource "aws_autoscaling_group" "asg_pass" {
  name                      = "asg-pass-example"
  launch_configuration      = aws_launch_configuration.lc.id
  min_size                  = 1
  max_size                  = 1
  vpc_zone_identifier       = [aws_subnet.example.id]

  tag {
    key                 = "Environment"
    value               = "Production"
    propagate_at_launch = true
  }
}

resource "aws_launch_configuration" "lc" {
  name          = "lc-pass-example"
  image_id      = "ami-12345678"
  instance_type = "t2.micro"
}

resource "aws_subnet" "example" {
  vpc_id     = aws_vpc.example.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_vpc" "example" {
  cidr_block = "10.0.0.0/16"
}
