provider "aws" {
  region = "us-west-2"
}

resource "aws_qldb_ledger" "failing_ledger" {
  name = "failing-ledger"
  deletion_protection = false
  permissions_mode = "STANDARD"
}
