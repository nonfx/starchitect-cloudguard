provider "aws" {
  region = "us-west-2"
}

# Create VPC for testing
resource "aws_vpc" "test_vpc" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "test-vpc"
  }
}

# Create single subnet
resource "aws_subnet" "subnet" {
  vpc_id = aws_vpc.test_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"
  
  tags = {
    Name = "subnet"
  }
}

# Create EC2 instance
resource "aws_instance" "test_instance" {
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  subnet_id = aws_subnet.subnet.id

  tags = {
    Name = "test-instance"
  }
}

# Create single network interface
resource "aws_network_interface" "eni" {
  subnet_id = aws_subnet.subnet.id
  
  tags = {
    Name = "eni"
  }
}

# Attach single ENI to the instance
resource "aws_network_interface_attachment" "attachment" {
  instance_id = aws_instance.test_instance.id
  network_interface_id = aws_network_interface.eni.id
  device_index = 0
}