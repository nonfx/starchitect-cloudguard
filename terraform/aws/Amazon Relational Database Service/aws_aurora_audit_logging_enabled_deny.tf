provider "aws" {
  region = "us-west-2"
}

resource "aws_cloudtrail" "example" {
  name                          = "example-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.example.id
  include_global_service_events = false
  is_multi_region_trail         = false
}

resource "aws_s3_bucket" "example" {
  bucket        = "example-cloudtrail-bucket"
  force_destroy = true
}

resource "aws_rds_cluster" "example" {
  cluster_identifier      = "aurora-cluster-demo"
  engine                  = "aurora-mysql"
  engine_version          = "5.7.mysql_aurora.2.03.2"
  availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
  database_name           = "mydb"
  master_username         = "foo"
  master_password         = "bar"
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
}

resource "aws_rds_cluster_instance" "example" {
  identifier         = "aurora-cluster-demo-instance"
  cluster_identifier = aws_rds_cluster.example.id
  instance_class     = "db.r5.large"
  engine             = aws_rds_cluster.example.engine
  engine_version     = aws_rds_cluster.example.engine_version
}

# No aws_rds_cluster_activity_stream resource, which will cause a policy violation
