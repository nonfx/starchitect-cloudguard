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

# Create two subnets in different AZs
resource "aws_subnet" "subnet_1" {
  vpc_id = aws_vpc.test_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"
  
  tags = {
    Name = "subnet-1"
  }
}

resource "aws_subnet" "subnet_2" {
  vpc_id = aws_vpc.test_vpc.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "us-west-2b"
  
  tags = {
    Name = "subnet-2"
  }
}

# Create EC2 instance
resource "aws_instance" "test_instance" {
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  subnet_id = aws_subnet.subnet_1.id

  tags = {
    Name = "test-instance"
  }
}

# Create multiple network interfaces
resource "aws_network_interface" "eni_1" {
  subnet_id = aws_subnet.subnet_1.id
  
  tags = {
    Name = "eni-1"
  }
}

resource "aws_network_interface" "eni_2" {
  subnet_id = aws_subnet.subnet_2.id
  
  tags = {
    Name = "eni-2"
  }
}

# Attach multiple ENIs to the instance
resource "aws_network_interface_attachment" "attachment_1" {
  instance_id = aws_instance.test_instance.id
  network_interface_id = aws_network_interface.eni_1.id
  device_index = 0
}

resource "aws_network_interface_attachment" "attachment_2" {
  instance_id = aws_instance.test_instance.id
  network_interface_id = aws_network_interface.eni_2.id
  device_index = 1
}