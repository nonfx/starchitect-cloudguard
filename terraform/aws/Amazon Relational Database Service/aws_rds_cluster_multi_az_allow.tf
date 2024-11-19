provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create RDS cluster with multi-AZ
resource "aws_rds_cluster" "pass_cluster" {
  provider = aws.pass_aws
  cluster_identifier = "pass-aurora-cluster"
  engine = "aurora-mysql"
  engine_version = "5.7.mysql_aurora.2.10.2"
  database_name = "mydb"
  master_username = "admin"
  master_password = "changeme123"
  availability_zones = ["us-west-2a", "us-west-2b", "us-west-2c"]
  
  backup_retention_period = 7
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot = true
  
  tags = {
    Environment = "production"
    Name = "multi-az-cluster"
  }
}