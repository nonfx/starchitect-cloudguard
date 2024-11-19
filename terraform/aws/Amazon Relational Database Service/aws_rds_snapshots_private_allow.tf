provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create RDS instance
resource "aws_db_instance" "pass_db" {
  provider = aws.pass_aws
  identifier = "pass-db-instance"
  engine = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  skip_final_snapshot = true

  # Enable encryption
  storage_encrypted = true
}

# Create private DB snapshot
resource "aws_db_snapshot" "pass_snapshot" {
  provider = aws.pass_aws
  db_instance_identifier = aws_db_instance.pass_db.id
  db_snapshot_identifier = "pass-snapshot"

  tags = {
    Environment = "production"
  }
}

# Create private cluster snapshot
resource "aws_db_cluster_snapshot" "pass_cluster_snapshot" {
  provider = aws.pass_aws
  db_cluster_identifier = "example-cluster"
  db_cluster_snapshot_identifier = "pass-cluster-snapshot"

  tags = {
    Environment = "production"
  }
}
