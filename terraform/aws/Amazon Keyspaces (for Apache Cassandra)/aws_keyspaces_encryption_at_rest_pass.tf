provider "aws" {
  region = "us-west-2"
}

resource "aws_kms_key" "example" {
  description             = "KMS key for Keyspaces encryption"
  deletion_window_in_days = 10
}

resource "aws_keyspaces_keyspace" "example" {
  name = "example_keyspace"
}

resource "aws_keyspaces_table" "passing_table" {
  keyspace_name = aws_keyspaces_keyspace.example.name
  table_name    = "passing_table"

  schema_definition {
    column {
      name = "id"
      type = "text"
    }

    partition_key {
      name = "id"
    }
  }

  encryption_specification {
    type                = "CUSTOMER_MANAGED_KMS_KEY"
    kms_key_identifier = aws_kms_key.example.arn
  }

  # for AWS owned keys
  #  encryption_specification {
  #   type                = "AWS_OWNED_KMS_KEY"

  # }
}
