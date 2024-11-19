provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_ecs_cluster" "fail_cluster" {
  provider = aws.fail_aws
  name = "fail-cluster"
}

resource "aws_ecs_task_definition" "fail_task" {
  provider = aws.fail_aws
  family = "fail-service"
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
  cpu = 256
  memory = 512

  container_definitions = jsonencode([
    {
      name = "fail-container"
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

resource "aws_ecs_service" "fail_service" {
  provider = aws.fail_aws
  name = "fail-service"
  cluster = aws_ecs_cluster.fail_cluster.id
  task_definition = aws_ecs_task_definition.fail_task.arn
  desired_count = 1
  launch_type = "FARGATE"
  platform_version = "1.3.0"  # Using outdated platform version

  network_configuration {
    assign_public_ip = false
    security_groups = ["sg-12345678"]
    subnets = ["subnet-12345678"]
  }

  tags = {
    Environment = "development"
  }
}
