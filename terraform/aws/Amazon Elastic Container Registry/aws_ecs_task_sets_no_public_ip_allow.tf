# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create ECS cluster
resource "aws_ecs_cluster" "pass_cluster" {
  name = "pass-cluster"
}

# Define ECS task definition
resource "aws_ecs_task_definition" "pass_task" {
  family = "pass-service"
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

# Create ECS service with public IP assignment disabled (passing configuration)
resource "aws_ecs_service" "pass_service" {
  name = "pass-service"
  cluster = aws_ecs_cluster.pass_cluster.id
  task_definition = aws_ecs_task_definition.pass_task.arn
  desired_count = 1

  network_configuration {
    subnets = ["subnet-12345678"]
    assign_public_ip = false  # This configuration will pass the policy check
  }
}