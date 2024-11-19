# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create a launch template with single instance type
resource "aws_launch_template" "fail_template" {
  name_prefix   = "fail-template"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
}

# Create an Auto Scaling group with single AZ and no mixed instances
resource "aws_autoscaling_group" "fail_asg" {
  name                = "fail-asg"
  availability_zones  = ["us-west-2a"]  # Single AZ
  desired_capacity    = 1
  max_size            = 1
  min_size            = 1

  # Simple launch template configuration without mixed instances
  launch_template {
    id      = aws_launch_template.fail_template.id
    version = "$Latest"
  }
}