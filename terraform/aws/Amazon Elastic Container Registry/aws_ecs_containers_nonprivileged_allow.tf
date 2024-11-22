provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_ecs_task_definition" "pass_task" {
  provider = aws.pass_aws
  family = "pass-service"
  
  # Container definition without privileged access (compliant)
  container_definitions = jsonencode([
    {
      name = "pass-container"
      image = "nginx:latest"
      cpu = 256
      memory = 512
      essential = true
      privileged = false  # This makes the configuration compliant
      
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

  # Additional security configurations
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture = "X86_64"
  }

  tags = {
    Environment = "Production"
    Security = "Compliant"
  }
}