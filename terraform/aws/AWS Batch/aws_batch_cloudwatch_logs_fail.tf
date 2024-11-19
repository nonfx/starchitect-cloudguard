provider "aws" {
  region = "us-west-2"
}

resource "aws_batch_job_definition" "failing_example" {
  name = "failing_batch_job_def"
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
    # No logConfiguration specified
  })
}
