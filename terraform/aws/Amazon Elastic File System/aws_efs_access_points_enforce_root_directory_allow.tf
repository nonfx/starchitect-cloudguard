# Configure AWS provider with specific region
provider "aws" {
  region = "us-west-2"
}

# Create EFS file system
resource "aws_efs_file_system" "pass_fs" {
  creation_token = "pass-efs"
  encrypted      = true

  tags = {
    Name = "pass-efs"
  }
}

# Create EFS access point with specific subdirectory (compliant)
resource "aws_efs_access_point" "pass_ap" {
  file_system_id = aws_efs_file_system.pass_fs.id

  root_directory {
    path = "/data"  # Compliant: Using specific subdirectory
    creation_info {
      owner_gid   = 1000
      owner_uid   = 1000
      permissions = "755"
    }
  }

  posix_user {
    gid = 1000
    uid = 1000
    secondary_gids = [2000, 3000]
  }

  tags = {
    Name = "pass-access-point"
    Environment = "Production"
  }
}