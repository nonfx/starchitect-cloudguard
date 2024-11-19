# Configure AWS provider for the failing test case
provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create Neptune cluster without deletion protection
resource "aws_neptune_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "neptune-cluster-fail"
  engine = "neptune"
  deletion_protection = false  # Deletion protection disabled

  tags = {
    Environment = "test"
  }
}
