resource "aws_backup_report_plan" "pass_example" {
  name = "example-report-plan"

  report_delivery_channel {
    formats = ["CSV"]
    s3_bucket_name = "example-bucket"
  }

  report_setting {
    report_template = "RESOURCE_COMPLIANCE_REPORT"
  }

  tags = {
    "Environment" = "Production"
    "Owner"       = "John Doe"
    "Project"     = "Example"
  }
}
