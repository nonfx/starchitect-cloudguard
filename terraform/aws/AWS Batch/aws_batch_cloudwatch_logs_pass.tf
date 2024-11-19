provider "aws" {
  region = "us-west-2"
}

resource "aws_batch_job_definition" "passing_example" {
  name = "passing_batch_job_def"
  type = "container"

  container_properties = jsonencode({
    image = "busybox"
    command = ["echo", "test"]
    resourceRequirements = [
      {
        type  = "VCPU"
        value = "1"
      },
      {
        type  = "MEMORY"
        value = "512"
      }
    ]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group" = "/aws/batch/job"
        "awslogs-region" = "us-west-2"
        "awslogs-stream-prefix" = "batch"
      }
    }
  })
}
