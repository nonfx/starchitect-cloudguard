provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_dms_replication_task" "fail_example" {
  provider = aws.fail_aws
  replication_task_id = "dms-replication-task-fail"
  migration_type      = "full-load"
  
  replication_instance_arn = aws_dms_replication_instance.test.replication_instance_arn
  source_endpoint_arn      = aws_dms_endpoint.source.endpoint_arn
  target_endpoint_arn      = aws_dms_endpoint.target.endpoint_arn
  
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

  # Invalid logging configuration
  replication_task_settings = jsonencode({
    "Logging": {
      "EnableLogging": false,
      "LogComponents": [
        {
          "Id": "SOURCE_CAPTURE",
          "Severity": "LOGGER_SEVERITY_ERROR"
        },
        {
          "Id": "SOURCE_UNLOAD",
          "Severity": "LOGGER_SEVERITY_ERROR"
        }
      ]
    }
  })
}
