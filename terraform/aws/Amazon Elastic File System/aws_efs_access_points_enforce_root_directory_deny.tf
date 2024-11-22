# Configure AWS provider with specific region
provider "aws" {
  region = "us-west-2"
}

# Create EFS file system
resource "aws_efs_file_system" "fail_fs" {
  creation_token = "fail-efs"
  encrypted      = true

  tags = {
    Name = "fail-efs"
  }
}

# Create EFS access point with root directory set to '/' (non-compliant)
resource "aws_efs_access_point" "fail_ap" {
  file_system_id = aws_efs_file_system.fail_fs.id

  root_directory {
    path = "/"  # Non-compliant: Using root directory
  }

  tags = {
    Name = "fail-access-point"
  }
}