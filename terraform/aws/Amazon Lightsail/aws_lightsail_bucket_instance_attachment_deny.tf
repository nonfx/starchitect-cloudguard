provider "aws" {
  region = "us-west-2"
}

# Create a Lightsail bucket
resource "aws_lightsail_bucket" "example_bucket" {
  name      = "my-example-bucket"
  bundle_id = "small_1_0"
}

# Create a Lightsail instance
resource "aws_lightsail_instance" "example_instance" {
  name              = "example-instance"
  availability_zone = "us-west-2a"
  blueprint_id      = "amazon_linux_2"
  bundle_id         = "nano_2_0"
}

# Note: No aws_lightsail_bucket_access_key resource is created,
# which means the bucket is not attached to any instance.
