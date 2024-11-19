provider "aws" {
  region = "us-west-2"
}

# Create a KMS key for encryption
resource "aws_kms_key" "pass_key" {
  description = "KMS key for RDS encryption"
  deletion_window_in_days = 7
}

# Create an encrypted RDS instance
resource "aws_db_instance" "pass_db" {
  identifier = "pass-db-instance"
  engine = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  skip_final_snapshot = true
  storage_encrypted = true
  kms_key_id = aws_kms_key.pass_key.arn
}

# Create an encrypted snapshot
resource "aws_db_snapshot" "pass_snapshot" {
  db_instance_identifier = aws_db_instance.pass_db.id
  db_snapshot_identifier = "pass-snapshot"
  encrypted = true
  kms_key_id = aws_kms_key.pass_key.arn
}

# Create an encrypted cluster
resource "aws_rds_cluster" "pass_cluster" {
  cluster_identifier = "pass-aurora-cluster"
  engine = "aurora-mysql"
  master_username = "admin"
  master_password = "password123"
  skip_final_snapshot = true
  storage_encrypted = true
  kms_key_id = aws_kms_key.pass_key.arn
}

# Create an encrypted cluster snapshot
resource "aws_db_cluster_snapshot" "pass_cluster_snapshot" {
  db_cluster_identifier = aws_rds_cluster.pass_cluster.id
  db_cluster_snapshot_identifier = "pass-cluster-snapshot"
  storage_encrypted = true
}
