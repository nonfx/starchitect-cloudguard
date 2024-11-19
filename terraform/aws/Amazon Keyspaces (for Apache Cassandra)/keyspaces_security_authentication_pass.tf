# Create a VPC
resource "aws_vpc" "keyspace_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "keyspace-vpc"
  }
}

# Create a security group for the Keyspace VPC endpoint
resource "aws_security_group" "keyspace_sg" {
  name_prefix = "keyspace-sg"
  vpc_id      = aws_vpc.keyspace_vpc.id

  ingress {
    from_port   = 9142
    to_port     = 9142
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Allow access from within the VPC
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Allow all outbound traffic
  }
}

# Create a subnet within the VPC
resource "aws_subnet" "keyspace_subnet" {
  vpc_id     = aws_vpc.keyspace_vpc.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "keyspace-subnet"
  }
}

# Create an interface VPC endpoint for Amazon Keyspaces
resource "aws_vpc_endpoint" "keyspace_endpoint" {
  vpc_id            = aws_vpc.keyspace_vpc.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.cassandra"
  vpc_endpoint_type = "Interface"
  subnet_ids        = [aws_subnet.keyspace_subnet.id]
  security_group_ids = [aws_security_group.keyspace_sg.id]

  private_dns_enabled = true
}

# Create a Keyspace
resource "aws_keyspaces_keyspace" "example_keyspace" {
  name = "example_keyspace"

  tags = {
    Environment = "dev"
  }
}

# Create a Keyspace table
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

data "aws_region" "current" {}
