provider "aws" {
  region = "us-west-2"
}

resource "aws_qldb_ledger" "passing_ledger" {
  name = "passing-ledger"
  deletion_protection = true
  permissions_mode = "ALLOW_ALL"
  kms_key = "arn:aws:kms:us-west-2:123456789012:key/abcd1234-a123-456a-a12b-a123b4cd56ef"
}
