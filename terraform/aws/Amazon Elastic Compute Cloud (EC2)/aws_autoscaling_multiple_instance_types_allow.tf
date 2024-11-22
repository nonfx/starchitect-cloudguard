# Create a launch template for the ASG
resource "aws_launch_template" "pass_template" {
  name_prefix   = "pass-template"
  image_id      = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
}

# Create a compliant Auto Scaling group
resource "aws_autoscaling_group" "pass_asg" {
  name               = "pass-asg"
  availability_zones = ["us-west-2a", "us-west-2b"] # Multiple AZs
  desired_capacity   = 2
  max_size           = 4
  min_size           = 2

  # Mixed instances policy with multiple instance types
  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.pass_template.id
        version            = "$Latest"
      }

      override {
        instance_type = "t2.micro"
      }

      override {
        instance_type = "t3.micro"
      }
    }
  }

  # Tags for resource identification
  tag {
    key                 = "Environment"
    value               = "Production"
    propagate_at_launch = true
  }
}
