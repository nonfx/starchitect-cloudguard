provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_transfer_server" "pass_server" {
  provider = aws.pass_aws
  protocols = ["SFTP", "FTPS"]
  
  endpoint_type = "PUBLIC"
  
  tags = {
    Environment = "production"
    Name        = "pass-transfer-server"
  }
  
  structured_log_destinations = ["arn:aws:logs:us-west-2:123456789012:log-group:/aws/transfer/server"]
}