# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create EFS file system without proper POSIX user configuration
resource "aws_efs_file_system" "fail_fs" {
  creation_token = "fail-efs"
  encrypted      = true

  tags = {
    Name = "fail-efs"
  }
}

# Create access point without POSIX user configuration
resource "aws_efs_access_point" "fail_ap" {
  file_system_id = aws_efs_file_system.fail_fs.id

  root_directory {
    path = "/data"
  }

  tags = {
    Name = "fail-access-point"
  }
}
