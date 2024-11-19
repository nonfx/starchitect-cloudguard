resource "aws_backup_vault" "example" {
  name = "example_backup_vault"
}

resource "aws_backup_plan" "example_fail" {
  name = "tf_example_backup_plan"

  rule {
    rule_name         = "tf_example_backup_rule"
    target_vault_name = aws_backup_vault.example.name
    schedule          = "cron(0 12 * * ? *)"
  }

  tags = {
    "aws:backup-plan" = "tf_example_backup_plan"
  }
}

resource "aws_backup_selection" "example_fail" {
  iam_role_arn = aws_iam_role.example.arn
  name         = "tf_example_backup_selection"
  plan_id      = aws_backup_plan.example_fail.id

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "backup"
    value = "true"
  }

}
