# Configure AWS provider with specific region
provider "aws" {
  region = "us-west-2"
}

# Create a launch configuration (non-compliant resource)
resource "aws_launch_configuration" "fail_lc" {
  name_prefix   = "fail-launch-config"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
}

# Create an Auto Scaling group using launch configuration (non-compliant)
resource "aws_autoscaling_group" "fail_asg" {
  name                 = "fail-asg"
  launch_configuration = aws_launch_configuration.fail_lc.name
  min_size             = 1
  max_size             = 3
  desired_capacity     = 1
  vpc_zone_identifier  = ["subnet-12345678"]

  tag {
    key                 = "Environment"
    value               = "production"
    propagate_at_launch = true
  }
}
