provider "aws" {
  region = "us-west-2"
}

# Task definition using secure parameter store for sensitive information
resource "aws_ecs_task_definition" "pass_task" {
  family                   = "secure-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512

  container_definitions = jsonencode([
    {
      name      = "secure-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
      environment = [
        {
          name  = "APP_ENV"
          value = "production"
        },
        {
          name  = "LOG_LEVEL"
          value = "info"
        }
      ]
      secrets = [
        {
          name      = "DB_PASSWORD"
          valueFrom = "arn:aws:ssm:us-west-2:123456789012:parameter/prod/db/password"
        },
        {
          name      = "API_KEY"
          valueFrom = "arn:aws:ssm:us-west-2:123456789012:parameter/prod/api/key"
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

  # Enable execution role for accessing SSM parameters
  execution_role_arn = aws_iam_role.ecs_task_execution_role.arn
}