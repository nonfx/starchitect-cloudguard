resource "aws_backup_vault" "fail_example" {
  name = "example-vault"

  tags = {
    "aws:backup:source-resource" = "example-resource"
  }
}
