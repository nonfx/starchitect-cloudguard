# Provider configuration
provider "aws" {
  region = "us-west-2"
}

# QLDB ledger with proper access control
resource "aws_qldb_ledger" "example_ledger" {
  name = "example-ledger"
  permissions_mode = "STANDARD"
}

# IAM policy with QLDB-specific permissions
resource "aws_iam_policy" "example_qldb_policy" {
  name        = "example-qldb-policy"
  path        = "/"
  description = "Example policy with QLDB permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "qldb:CreateLedger",
          "qldb:DescribeLedger",
          "qldb:ListLedgers",
          "qldb:CreateTable",
          "qldb:GetTableInfo",
          "qldb:ListTables",
          "qldb:ReadDocument",
          "qldb:InsertDocument",
          "qldb:UpdateDocument",
          "qldb:DeleteDocument"
        ]
        Resource = aws_qldb_ledger.example_ledger.arn
      },
    ]
  })
}
