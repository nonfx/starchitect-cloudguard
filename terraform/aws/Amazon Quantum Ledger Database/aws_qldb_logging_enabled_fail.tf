provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_qldb_ledger" "failing_example" {
  provider = aws.failing
  name     = "failing-example"
  permissions_mode = "ALLOW_ALL"
}
