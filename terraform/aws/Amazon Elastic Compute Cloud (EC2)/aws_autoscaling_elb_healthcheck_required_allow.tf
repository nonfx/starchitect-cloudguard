provider "aws" {
  region = "us-west-2"
}

# Launch template configuration for EC2 instances
resource "aws_launch_template" "pass_template" {
  name_prefix   = "pass-template"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
}

# Application Load Balancer configuration
resource "aws_lb" "pass_lb" {
  name               = "pass-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678", "subnet-87654321"]
}

# Target group with health check configuration
resource "aws_lb_target_group" "pass_tg" {
  name     = "pass-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "vpc-12345678"

  health_check {
    enabled             = true
    healthy_threshold   = 3
    interval            = 30
    timeout             = 5
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    unhealthy_threshold = 2
  }
}

# Auto Scaling Group with ELB health checks (passing configuration)
resource "aws_autoscaling_group" "pass_asg" {
  name                      = "pass-asg"
  desired_capacity          = 1
  max_size                  = 3
  min_size                  = 1
  target_group_arns         = [aws_lb_target_group.pass_tg.arn]
  vpc_zone_identifier       = ["subnet-12345678", "subnet-87654321"]
  health_check_type         = "ELB" # Correct: Using ELB health checks
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.pass_template.id
    version = "$Latest"
  }

  tag {
    key                 = "Environment"
    value               = "Production"
    propagate_at_launch = true
  }
}
