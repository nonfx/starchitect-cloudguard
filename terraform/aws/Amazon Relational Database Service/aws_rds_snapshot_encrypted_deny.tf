provider "aws" {
  region = "us-west-2"
}

# Create an unencrypted RDS instance
resource "aws_db_instance" "fail_db" {
  identifier = "fail-db-instance"
  engine = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  skip_final_snapshot = true
  storage_encrypted = false
}

# Create an unencrypted snapshot
resource "aws_db_snapshot" "fail_snapshot" {
  db_instance_identifier = aws_db_instance.fail_db.id
  db_snapshot_identifier = "fail-snapshot"
  encrypted = false
}

# Create an unencrypted cluster
resource "aws_rds_cluster" "fail_cluster" {
  cluster_identifier = "fail-aurora-cluster"
  engine = "aurora-mysql"
  master_username = "admin"
  master_password = "password123"
  skip_final_snapshot = true
  storage_encrypted = false
}

# Create an unencrypted cluster snapshot
resource "aws_db_cluster_snapshot" "fail_cluster_snapshot" {
  db_cluster_identifier = aws_rds_cluster.fail_cluster.id
  db_cluster_snapshot_identifier = "fail-cluster-snapshot"
}