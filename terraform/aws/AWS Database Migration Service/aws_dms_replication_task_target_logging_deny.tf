provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_dms_replication_task" "fail_example" {
  provider = aws.fail_aws
  replication_task_id = "fail-dms-replication-task"
  migration_type      = "full-load"
  
  replication_instance_arn = "arn:aws:dms:us-west-2:123456789012:rep:EXAMPLE"
  source_endpoint_arn      = "arn:aws:dms:us-west-2:123456789012:endpoint:EXAMPLE1"
  target_endpoint_arn      = "arn:aws:dms:us-west-2:123456789012:endpoint:EXAMPLE2"
  
  table_mappings = jsonencode({
    "rules": [{
      "rule-type": "selection",
      "rule-id": "1",
      "rule-name": "1",
      "object-locator": {
        "schema-name": "%",
        "table-name": "%"
      },
      "rule-action": "include"
    }]
  })

  replication_task_settings = jsonencode({
    "Logging": {
      "EnableLogging": false,
      "LogComponents": [
        {
          "Id": "TARGET_APPLY",
          "Severity": "LOGGER_SEVERITY_OFF"
        },
        {
          "Id": "TARGET_LOAD",
          "Severity": "LOGGER_SEVERITY_OFF"
        }
      ]
    }
  })
}
