# Configure AWS Provider
provider "aws" {
  region = "us-west-2"
}

# Create DynamoDB table without autoscaling
resource "aws_dynamodb_table" "fail_test" {
  name           = "fail-test-table"
  billing_mode   = "PROVISIONED"  # Using provisioned mode without autoscaling
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Environment = "test"
    Purpose     = "fail-test"
  }
}
