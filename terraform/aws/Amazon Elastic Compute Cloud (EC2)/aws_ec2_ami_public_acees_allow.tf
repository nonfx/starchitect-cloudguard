resource "aws_ami" "ami_pass" {
  name               = "private-ami"
  virtualization_type = "hvm"
  root_device_name    = "/dev/sda1"
  ebs_block_device {
    device_name           = "/dev/sda1"
    volume_size           = 8
    delete_on_termination = true
    encrypted             = true
  }
  # No public launch permissions are set
}

# Ensure no public launch permissions are attached
resource "aws_ami_launch_permission" "private_permissions" {
  image_id = aws_ami.ami_pass.id
  # No permissions granted
}
