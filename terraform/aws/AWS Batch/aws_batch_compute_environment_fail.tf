provider "aws" {
  region = "us-east-1"  # Change to your desired region
}

resource "aws_iam_role" "batch_service_role_pass" {
  name = "BatchServiceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "batch.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "batch_policy_pass" {
  name = "BatchPolicy"
  role = aws_iam_role.batch_service_role.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "batch:SubmitJob",
          "batch:DescribeJobs",
          "batch:TerminateJob",
          "batch:ListJobs",
          "batch:DescribeJobDefinitions",
          "batch:DescribeJobQueues"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_batch_compute_environment" "batch_compute_pass" {
  compute_environment_name = "BatchComputeEnv"
  type                     = "MANAGED"

  compute_resources {
    type              = "EC2"
    min_vcpus        = 0
    max_vcpus        = 16
    desired_vcpus    = 4
    security_group_ids = ["sg-xxxxxxxx"]  # Replace with your security group ID
    subnets          = ["subnet-xxxxxxxx"]  # Replace with your subnet IDs

    tags = {
      Name = "BatchComputeInstance"
    }
  }

  service_role = aws_iam_role.batch_service_role_pass.arn
}
