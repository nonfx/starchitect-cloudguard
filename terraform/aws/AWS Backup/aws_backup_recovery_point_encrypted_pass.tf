resource "aws_backup_plan" "example_pass" {
  name = "tf_example_backup_plan"

  rule {
    rule_name         = "tf_example_backup_rule"
    target_vault_name = aws_backup_vault.test.name
    schedule          = "cron(0 12 * * ? *)"

    lifecycle {
      delete_after = 14
    }

    enable_continuous_backup = true
  }
}

resource "aws_backup_vault" "test" {
  name = "example_backup_vault"
  kms_key_arn = aws_kms_key.example.arn
}

resource "aws_kms_key" "example" {
  description             = "KMS key for backup vault encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}
