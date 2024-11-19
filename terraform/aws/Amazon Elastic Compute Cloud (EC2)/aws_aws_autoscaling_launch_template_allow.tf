# Configure AWS provider with specific region
provider "aws" {
  region = "us-west-2"
}

# Create a launch template (compliant resource)
resource "aws_launch_template" "pass_lt" {
  name_prefix   = "pass-launch-template"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # Configure instance metadata options for security
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = {
    Environment = "Production"
  }
}

# Create an Auto Scaling group using launch template (compliant)
resource "aws_autoscaling_group" "pass_asg" {
  name                = "pass-asg"
  vpc_zone_identifier = ["subnet-12345678"]
  min_size            = 1
  max_size            = 3
  desired_capacity    = 1

  # Use launch template instead of launch configuration
  launch_template {
    id      = aws_launch_template.pass_lt.id
    version = "$Latest"
  }

  tag {
    key                 = "Environment"
    value               = "production"
    propagate_at_launch = true
  }
}
