resource "aws_athena_workgroup" "example_pass_sse_s3" {
  name = "example-athena-workgroup-sse-s3"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://my-athena-result-bucket/output/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}

resource "aws_athena_workgroup" "example_pass_sse_kms" {
  name = "example-athena-workgroup-sse-kms"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://my-athena-result-bucket/output/"
      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
      }
    }
  }
}

resource "aws_athena_workgroup" "example_pass_cse_kms" {
  name = "example-athena-workgroup-cse-kms"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://my-athena-result-bucket/output/"
      encryption_configuration {
        encryption_option = "CSE_KMS"
        kms_key_arn       = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
      }
    }
  }
}
