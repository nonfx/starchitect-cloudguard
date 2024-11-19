resource "aws_ami" "ami_fail" {
  name               = "public-ami"
  virtualization_type = "hvm"
  root_device_name    = "/dev/sda1"
  ebs_block_device {
    device_name           = "/dev/sda1"
    volume_size           = 8
    delete_on_termination = true
    encrypted             = true
  }
}

resource "aws_ami_launch_permission" "public_permissions" {
  image_id = aws_ami.ami_fail.id
  group    = "all"  # Makes the AMI public
}
