resource "aws_timestreamwrite_database" "example" {
  database_name = "example-timestream-db"
}

resource "aws_timestreamwrite_table" "example_table" {
  database_name = aws_timestreamwrite_database.example.database_name
  table_name    = "example-table"
  retention_properties {
    memory_store_retention_period_in_hours = 24
    magnetic_store_retention_period_in_days = 7
  }
}

