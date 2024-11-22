provider "aws" {
  region = "us-west-2"
}

resource "aws_keyspaces_keyspace" "example" {
  name = "example_keyspace"
}

resource "aws_keyspaces_table" "failing_table" {
  keyspace_name = aws_keyspaces_keyspace.example.name
  table_name    = "failing_table"
  
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
    type = "AWS_OWNED_KMS_KEY"
  }
}
