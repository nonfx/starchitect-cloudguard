provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create RDS cluster without multi-AZ
resource "aws_rds_cluster" "fail_cluster" {
  provider = aws.fail_aws
  cluster_identifier = "fail-aurora-cluster"
  engine = "aurora-mysql"
  engine_version = "5.7.mysql_aurora.2.10.2"
  database_name = "mydb"
  master_username = "admin"
  master_password = "changeme123"
  availability_zones = ["us-west-2a"]
  
  tags = {
    Environment = "test"
  }
}