# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create EFS file system with encryption
resource "aws_efs_file_system" "pass_fs" {
  creation_token = "pass-efs"
  encrypted      = true

  tags = {
    Name = "pass-efs"
  }
}

# Create access point with proper POSIX user configuration
resource "aws_efs_access_point" "pass_ap" {
  file_system_id = aws_efs_file_system.pass_fs.id

  # Configure root directory settings
  root_directory {
    path = "/data"
    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = "755"
    }
  }

  # Configure POSIX user identity
  posix_user {
    gid = 1000
    uid = 1000
    secondary_gids = [1001, 1002]
  }

  tags = {
    Name = "pass-access-point"
  }
}
