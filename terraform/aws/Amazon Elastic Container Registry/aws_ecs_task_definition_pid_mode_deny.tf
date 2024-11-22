# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create an ECS task definition with insecure PID mode configuration
resource "aws_ecs_task_definition" "fail_task" {
  family = "fail-service"
  pid_mode = "host"  # This is insecure as it shares the host's process namespace
  
  # Define container specifications
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
          protocol = "tcp"
        }
      ]
    }
  ])

  # Add required task role
  requires_compatibilities = ["FARGATE"]
  network_mode = "awsvpc"
  cpu = "256"
  memory = "512"
}