provider "aws" {
  region = "us-west-2"
}

# Insecure ECS task definition with root user and privileged mode
resource "aws_ecs_task_definition" "fail_task" {
  family                = "insecure-task"
  network_mode          = "host"  # Using host network mode

  container_definitions = jsonencode([
    {
      name      = "insecure-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
      user      = "root"     # Insecure: Running as root
      privileged = true      # Insecure: Running in privileged mode

      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
          protocol      = "tcp"
        }
      ]
    }
  ])
}
