provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_ecs_cluster" "pass_cluster" {
  provider = aws.pass_aws
  name = "pass-cluster"
}

resource "aws_ecs_task_definition" "pass_task" {
  provider = aws.pass_aws
  family = "pass-service"
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
  cpu = 256
  memory = 512

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
          hostPort = 80
        }
      ]
    }
  ])
}

resource "aws_ecs_service" "pass_service" {
  provider = aws.pass_aws
  name = "pass-service"
  cluster = aws_ecs_cluster.pass_cluster.id
  task_definition = aws_ecs_task_definition.pass_task.arn
  desired_count = 1
  launch_type = "FARGATE"
  platform_version = "1.4.0"  # Using latest Linux platform version

  network_configuration {
    assign_public_ip = false
    security_groups = ["sg-12345678"]
    subnets = ["subnet-12345678"]
  }

  tags = {
    Environment = "production"
  }
}
