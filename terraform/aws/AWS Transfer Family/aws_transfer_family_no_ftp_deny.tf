provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_transfer_server" "fail_server" {
  provider = aws.fail_aws
  protocols = ["FTP", "SFTP"]
  
  endpoint_type = "PUBLIC"
  
  tags = {
    Environment = "development"
    Name        = "fail-transfer-server"
  }
}