# Provider configuration
provider "google" {
  project = "my-project"
  region  = "us-central1"
}

# Non-compliant PostgreSQL instance
resource "google_sql_database_instance" "fail_instance" {
  name             = "fail-postgres-instance"
  database_version = "POSTGRES_13"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "log_connections"
      value = "off"  # Non-compliant: log_connections is set to off
    }
  }
}
