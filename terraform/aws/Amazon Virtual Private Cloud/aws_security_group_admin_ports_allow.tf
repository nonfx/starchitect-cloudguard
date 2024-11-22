provider "aws" {
  region = "us-west-2"
}

# Replace with your actual IP addresses
variable "trusted_ssh_ip" {
  description = "IP address allowed for SSH access"
  default     = "203.0.113.1/32" # Replace with your trusted IP address
}

variable "trusted_rdp_ip_range" {
  description = "IP address range allowed for RDP access"
  default     = "203.0.113.0/24" # Replace with your trusted IP range
}

resource "aws_security_group" "remote_admin" {
  name        = "remote_admin_sg"
  description = "Security group to allow restricted SSH and RDP access"
  vpc_id      = "vpc-xxxxxxxx" # Replace with your VPC ID

  # Allow inbound traffic on port 22 (SSH) from trusted IP address
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.trusted_ssh_ip]
  }

  # Allow inbound traffic on port 3389 (RDP) from trusted IP range
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.trusted_rdp_ip_range]
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
