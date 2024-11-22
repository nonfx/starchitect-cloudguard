provider "aws" {
  region = "us-west-2"
}

resource "aws_security_group" "remote_admin" {
  name        = "remote_admin_sg"
  description = "Security group to allow SSH and RDP access from anywhere"
  vpc_id      = "vpc-xxxxxxxx" # Replace with your VPC ID

  # Allow inbound traffic on port 22 (SSH) from any IP address
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow inbound traffic on port 3389 (RDP) from any IP address
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1" # -1 means all protocols
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "remote_admin_sg"
  }
}
