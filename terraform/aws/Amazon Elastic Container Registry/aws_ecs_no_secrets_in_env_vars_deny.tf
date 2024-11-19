provider "aws" {
  region = "us-west-2"
}

# Task definition with sensitive information in environment variables
resource "aws_ecs_task_definition" "fail_task" {
  family                   = "sensitive-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512

  container_definitions = jsonencode([
    {
      name      = "sensitive-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
      environment = [
        {
          name  = "AWS_ACCESS_KEY_ID"
          value = "AKIAIOSFODNN7EXAMPLE"
        },
        {
          name  = "DATABASE_PASSWORD"
          value = "supersecret123"
        }
      ]
      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
        }
      ]
    }
  ])
}