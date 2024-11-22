# Configure AWS provider for the passing test case
provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create Neptune cluster with deletion protection enabled
resource "aws_neptune_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "neptune-cluster-pass"
  engine = "neptune"
  deletion_protection = true  # Deletion protection enabled

  tags = {
    Environment = "production"
  }
}
