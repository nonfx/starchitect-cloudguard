provider "aws" {
  region = "us-west-2"
}

# Create CloudWatch log group for container logs
resource "aws_cloudwatch_log_group" "pass_log_group" {
  name = "/ecs/pass-service"
  retention_in_days = 30
}

resource "aws_ecs_task_definition" "pass_task" {
  family = "pass-service"
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
  cpu = 256
  memory = 512

  # Container definition with proper logging configuration
  container_definitions = jsonencode([
    {
      name = "pass-container"
      image = "nginx:latest"
      essential = true
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group" = aws_cloudwatch_log_group.pass_log_group.name
          "awslogs-region" = "us-west-2"
          "awslogs-stream-prefix" = "ecs"
        }
      }
      portMappings = [
        {
          containerPort = 80
          protocol = "tcp"
        }
      ]
    }
  ])
}
