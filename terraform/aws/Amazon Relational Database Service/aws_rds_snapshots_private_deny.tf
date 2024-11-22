provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create RDS instance
resource "aws_db_instance" "fail_db" {
  provider = aws.fail_aws
  identifier = "fail-db-instance"
  engine = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  skip_final_snapshot = true
}

# Create public DB snapshot
resource "aws_db_snapshot" "fail_snapshot" {
  provider = aws.fail_aws
  db_instance_identifier = aws_db_instance.fail_db.id
  db_snapshot_identifier = "fail-snapshot"
  shared_accounts = ["all"]

  tags = {
    Environment = "test"
  }
}

# Create public cluster snapshot
resource "aws_db_cluster_snapshot" "fail_cluster_snapshot" {
  provider = aws.fail_aws
  db_cluster_identifier = "example-cluster"
  db_cluster_snapshot_identifier = "fail-cluster-snapshot"
  shared_accounts = ["all"]

  tags = {
    Environment = "test"
  }
}
