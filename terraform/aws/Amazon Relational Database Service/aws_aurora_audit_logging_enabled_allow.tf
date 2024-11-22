provider "aws" {
  region = "us-west-2"
}

resource "aws_cloudtrail" "example" {
  name                          = "example-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.example.id
  include_global_service_events = true
  is_multi_region_trail         = true
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
}

resource "aws_rds_cluster_instance" "example" {
  identifier         = "aurora-cluster-demo-instance"
  cluster_identifier = aws_rds_cluster.example.id
  instance_class     = "db.r5.large"
  engine             = aws_rds_cluster.example.engine
  engine_version     = aws_rds_cluster.example.engine_version
}

resource "aws_kms_key" "example" {
  description = "KMS key for RDS cluster activity stream"
}

resource "aws_rds_cluster_activity_stream" "example" {
  resource_arn = aws_rds_cluster.example.arn
  mode         = "async"
  kms_key_id   = aws_kms_key.example.key_id

  depends_on = [aws_rds_cluster_instance.example]
}
