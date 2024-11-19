resource "aws_workspaces_workspace" "fail_example" {
  directory_id = aws_workspaces_directory.example.id
  bundle_id    = "wsb-b0s22j3d7"
  user_name    = "example-user"

  root_volume_encryption_enabled = false
  user_volume_encryption_enabled = true

  workspace_properties {
    compute_type_name                         = "VALUE"
    user_volume_size_gib                      = 10
    root_volume_size_gib                      = 80
    running_mode                              = "AUTO_STOP"
    running_mode_auto_stop_timeout_in_minutes = 60
  }

  tags = {
    Name = "example-workspace"
  }
}
