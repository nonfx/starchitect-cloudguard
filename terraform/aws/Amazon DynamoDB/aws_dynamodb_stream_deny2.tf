provider "aws" {
  region = "us-west-2"
}

# Create the DynamoDB table with Streams enabled
resource "aws_dynamodb_table" "example_table" {
  name           = "example-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"
  stream_enabled = true
  stream_view_type = "NEW_IMAGE"  # Capture only the new image of the item

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "example-table"
    Environment = "Production"
  }
}
