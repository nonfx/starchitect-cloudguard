# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create an ECS task definition with secure configuration (no host PID mode)
resource "aws_ecs_task_definition" "pass_task" {
  family = "pass-service"
  # No pid_mode specified, which defaults to private namespace
  
  # Define container specifications
  container_definitions = jsonencode([
    {
      name = "pass-container"
      image = "nginx:latest"
      cpu = 256
      memory = 512
      essential = true
      
      portMappings = [
        {
          containerPort = 80
          protocol = "tcp"
        }
      ]
    }
  ])

  # Configure runtime platform
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture = "X86_64"
  }

  # Add required task role
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
  cpu = "256"
  memory = "512"

  # Add tags for better resource management
  tags = {
    Environment = "Production"
    Security = "Compliant"
  }
}