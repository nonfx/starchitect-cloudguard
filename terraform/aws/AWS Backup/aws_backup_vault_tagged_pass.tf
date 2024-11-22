resource "aws_backup_vault" "pass_example" {
  name = "example-vault"

  tags = {
    "Environment" = "Production"
    "Owner"       = "John Doe"
    "Project"     = "Example"
  }
}
