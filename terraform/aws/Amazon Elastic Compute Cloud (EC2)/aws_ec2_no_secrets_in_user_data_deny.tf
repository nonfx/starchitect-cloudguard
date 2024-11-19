provider "aws" {
  region = "us-west-2"
}

resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  user_data = <<-EOF
              #!/bin/bash
              echo "This is a secret password: MySecretPass123!"
              echo "API Key: abcdef123456"
              EOF

  tags = {
    Name = "example-instance"
  }
}
