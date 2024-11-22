provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_vpc" "passing_vpc" {
  provider   = aws.passing
  cidr_block = "10.0.0.0/16"
}

resource "aws_dynamodb_table" "passing_table" {
  provider     = aws.passing
  name         = "passing-dynamodb-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

data "aws_vpc_endpoint_service" "dynamodb" {
  provider      = aws.passing
  service       = "dynamodb"
  service_type  = "Gateway"
}

resource "aws_vpc_endpoint" "dynamodb" {
  provider        = aws.passing
  vpc_id          = aws_vpc.passing_vpc.id
  service_name    = data.aws_vpc_endpoint_service.dynamodb.service_name
  route_table_ids = [aws_vpc.passing_vpc.default_route_table_id]
}
