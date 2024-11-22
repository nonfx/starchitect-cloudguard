provider "aws" {
  region = "us-west-2"
}

# Launch template configuration for EC2 instances
resource "aws_launch_template" "fail_template" {
  name_prefix   = "fail-template"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
}

# Application Load Balancer configuration
resource "aws_lb" "fail_lb" {
  name               = "fail-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678", "subnet-87654321"]
}

# Target group for the load balancer
resource "aws_lb_target_group" "fail_tg" {
  name     = "fail-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "vpc-12345678"
}

# Auto Scaling Group with EC2 health checks (failing configuration)
resource "aws_autoscaling_group" "fail_asg" {
  name                = "fail-asg"
  desired_capacity    = 1
  max_size            = 3
  min_size            = 1
  target_group_arns   = [aws_lb_target_group.fail_tg.arn]
  vpc_zone_identifier = ["subnet-12345678", "subnet-87654321"]
  health_check_type   = "EC2"  # Incorrect: Using EC2 health checks instead of ELB

  launch_template {
    id      = aws_launch_template.fail_template.id
    version = "$Latest"
  }
}