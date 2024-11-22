resource "aws_backup_plan" "pass_example" {
  name = "example-backup-plan"

  rule {
    rule_name         = "example-rule"
    target_vault_name = "example-vault"
    schedule          = "cron(0 12 * * ? *)"
  }

  tags = {
    "Environment" = "Production"
    "Owner"       = "John Doe"
    "Project"     = "Example"
  }
}
