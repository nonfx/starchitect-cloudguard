provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create ECS cluster
resource "aws_ecs_cluster" "pass_cluster" {
  provider = aws.pass_aws
  name     = "pass-cluster"
}

# Create ECS task definition
resource "aws_ecs_task_definition" "pass_task" {
  provider    = aws.pass_aws
  family      = "pass-service"
  network_mode = "awsvpc"

  container_definitions = jsonencode([
    {
      name      = "pass-container"
      image     = "nginx:latest"
      cpu       = 256
      memory    = 512
      essential = true
    }
  ])
}

# Create ECS service with public IP disabled - This will pass the policy check
resource "aws_ecs_service" "pass_service" {
  provider          = aws.pass_aws
  name              = "pass-service"
  cluster           = aws_ecs_cluster.pass_cluster.id
  task_definition   = aws_ecs_task_definition.pass_task.arn
  desired_count     = 1

  network_configuration {
    assign_public_ip = false
    security_groups  = ["sg-12345678"]
    subnets         = ["subnet-12345678"]
  }

  tags = {
    Environment = "production"
  }
}
