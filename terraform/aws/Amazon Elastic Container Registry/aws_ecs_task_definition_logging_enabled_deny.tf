provider "aws" {
  region = "us-west-2"
}

resource "aws_ecs_task_definition" "fail_task" {
  family = "fail-service"
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
  cpu = 256
  memory = 512

  # Container definition without logging configuration
  container_definitions = jsonencode([
    {
      name = "fail-container"
      image = "nginx:latest"
      essential = true
      portMappings = [
        {
          containerPort = 80
          protocol = "tcp"
        }
      ]
    }
  ])
}