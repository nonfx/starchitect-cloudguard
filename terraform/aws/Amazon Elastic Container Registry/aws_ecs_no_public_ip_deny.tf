provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create ECS cluster
resource "aws_ecs_cluster" "fail_cluster" {
  provider = aws.fail_aws
  name     = "fail-cluster"
}

# Create ECS task definition
resource "aws_ecs_task_definition" "fail_task" {
  provider    = aws.fail_aws
  family      = "fail-service"
  network_mode = "awsvpc"

  container_definitions = jsonencode([
    {
      name      = "fail-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
    }
  ])
}

# Create ECS service with public IP enabled - This will fail the policy check
resource "aws_ecs_service" "fail_service" {
  provider          = aws.fail_aws
  name              = "fail-service"
  cluster           = aws_ecs_cluster.fail_cluster.id
  task_definition   = aws_ecs_task_definition.fail_task.arn
  desired_count     = 1

  network_configuration {
    assign_public_ip = true
    security_groups  = ["sg-12345678"]
    subnets         = ["subnet-12345678"]
  }

  tags = {
    Environment = "test"
  }
}
