provider "aws" {
  region = "us-west-2"
}

resource "aws_neptune_cluster" "secure_neptune" {
  cluster_identifier = "secure-neptune-cluster"
  engine = "neptune"
  skip_final_snapshot = true
}
