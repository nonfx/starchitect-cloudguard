# Configure AWS provider for the failing test case
provider "aws" {
  region = "us-west-2"
}

# Create an ECS task definition that will fail the policy check
resource "aws_ecs_task_definition" "fail_task" {
  family                = "fail-service"
  requires_compatibilities = ["FARGATE"]
  network_mode          = "awsvpc"
  cpu                   = 256
  memory                = 512

  # Container definition with readonly_root_filesystem set to false
  container_definitions = jsonencode([
    {
      name      = "fail-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
      readonlyRootFilesystem = false

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
}
