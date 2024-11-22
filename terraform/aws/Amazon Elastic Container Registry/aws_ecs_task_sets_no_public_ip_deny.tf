# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create ECS cluster
resource "aws_ecs_cluster" "fail_cluster" {
  name = "fail-cluster"
}

# Define ECS task definition
resource "aws_ecs_task_definition" "fail_task" {
  family = "fail-service"
  container_definitions = jsonencode([
    {
      name = "first"
      image = "nginx"
      cpu = 10
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

# Create ECS service with public IP assignment enabled (failing configuration)
resource "aws_ecs_service" "fail_service" {
  name = "fail-service"
  cluster = aws_ecs_cluster.fail_cluster.id
  task_definition = aws_ecs_task_definition.fail_task.arn
  desired_count = 1

  network_configuration {
    subnets = ["subnet-12345678"]
    assign_public_ip = true  # This configuration will fail the policy check
  }
}