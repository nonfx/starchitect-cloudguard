resource "aws_kms_key" "pass_key" {
  description = "KMS key for Redshift cluster encryption"
  enable_key_rotation = true
}

resource "aws_redshift_cluster" "pass_test" {
  cluster_identifier = "pass-redshift-cluster"
  database_name      = "passdb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  number_of_nodes    = 1
  
  # Enable encryption with KMS key
  encrypted = true
  kms_key_id = aws_kms_key.pass_key.arn

  tags = {
    Environment = "production"
  }
}
