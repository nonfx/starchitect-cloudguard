# Provider configuration
provider "aws" {
  region = var.region
}

# Create a Keyspace
resource "aws_keyspaces_keyspace" "example_keyspace" {
  name = "example_keyspace"

  tags = {
    Environment = "dev"
  }
}

# Create a Keyspace table without VPC endpoint and security group
resource "aws_keyspaces_table" "example_table" {
  keyspace_name = aws_keyspaces_keyspace.example_keyspace.name
  table_name    = "example_table"

  schema_definition {
    column {
      name = "id"
      type = "text"
    }
    partition_key {
      name = "id"
    }
  }

  capacity_specification {
    throughput_mode = "PAY_PER_REQUEST"
  }

  point_in_time_recovery {
    status = "ENABLED"
  }

  encryption_specification {
    type = "AWS_OWNED_KMS_KEY"
  }

  tags = {
    Environment = "dev"
  }
}

# Variables
variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}
