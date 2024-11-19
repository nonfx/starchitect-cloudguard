# Configure AWS provider for the passing test case
provider "aws" {
  region = "us-west-2"
}

# Create an ECS task definition that will pass the policy check
resource "aws_ecs_task_definition" "pass_task" {
  family                = "pass-service"
  requires_compatibilities = ["FARGATE"]
  network_mode          = "awsvpc"
  cpu                   = 256
  memory                = 512

  # Container definition with readonly_root_filesystem set to true
  container_definitions = jsonencode([
    {
      name      = "pass-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
      readonlyRootFilesystem = true

      portMappings = [
        {
          containerPort = 80
          protocol      = "tcp"
        }
      ]
    }
  ])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture       = "X86_64"
  }

  tags = {
    Environment = "Production"
    Security    = "Compliant"
  }
}
