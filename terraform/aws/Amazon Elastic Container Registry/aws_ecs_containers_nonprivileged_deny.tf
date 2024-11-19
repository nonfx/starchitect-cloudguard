provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_ecs_task_definition" "fail_task" {
  provider = aws.fail_aws
  family = "fail-service"
  
  # Container definition with privileged access (non-compliant)
  container_definitions = jsonencode([
    {
      name = "fail-container"
      image = "nginx:latest"
      cpu = 256
      memory = 512
      essential = true
      privileged = true  # This makes the configuration non-compliant
      
      portMappings = [
        {
          containerPort = 80
          protocol = "tcp"
        }
      ]
    }
  ])

  # Required task definition settings
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
  cpu = 256
  memory = 512
}