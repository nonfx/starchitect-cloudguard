resource "aws_ami" "ami_fail" {
  name               = "unencrypted-ami"
  virtualization_type = "hvm"
  root_device_name    = "/dev/sda1"
  ebs_block_device {
    device_name           = "/dev/sda1"
    volume_size           = 8
    delete_on_termination = true
    encrypted             = false
  }
}
