# Create Classic Load Balancer without logging enabled
resource "aws_elb" "fail_example" {
  name               = "fail-elb"
  availability_zones = ["us-west-2a"]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  # No access_logs block defined
  tags = {
    Environment = "test"
  }
}

# Create Application Load Balancer without logging enabled
resource "aws_lb" "fail_example" {
  name               = "fail-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678"]

  # No access_logs block defined
  tags = {
    Environment = "test"
  }
}
