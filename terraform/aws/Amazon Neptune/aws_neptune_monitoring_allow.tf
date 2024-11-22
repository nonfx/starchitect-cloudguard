provider "aws" {
  region = "us-west-2"
}

resource "aws_neptune_cluster" "pass_example" {
  cluster_identifier = "neptune-cluster-example"
  engine = "neptune"
  skip_final_snapshot = true
  enable_cloudwatch_logs_exports = ["audit"]
}
