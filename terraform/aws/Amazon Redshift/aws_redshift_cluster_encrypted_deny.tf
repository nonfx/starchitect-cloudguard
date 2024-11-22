resource "aws_redshift_cluster" "fail_test" {
  cluster_identifier = "fail-redshift-cluster"
  database_name      = "faildb"
  master_username    = "admin"
  master_password    = "Test1234!"
  node_type          = "dc2.large"
  number_of_nodes    = 1
  
  # Encryption disabled
  encrypted = false

  tags = {
    Environment = "test"
  }
}
