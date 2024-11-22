provider "aws" {
  region = "us-west-2"
}

# Secure ECS task definition with non-root user and no privileged mode
resource "aws_ecs_task_definition" "pass_task" {
  family                = "secure-task"
  network_mode          = "host"  # Using host network mode securely

  container_definitions = jsonencode([
    {
      name      = "secure-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
      user      = "nginx"    # Secure: Running as non-root user
      privileged = false     # Secure: Not running in privileged mode

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
