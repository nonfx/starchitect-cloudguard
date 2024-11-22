# Provider configuration
provider "google" {
  project = "my-project"
  region  = "us-central1"
}

# Compliant PostgreSQL instance
resource "google_sql_database_instance" "pass_instance" {
  name             = "pass-postgres-instance"
  database_version = "POSTGRES_13"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "log_connections"
      value = "on"  # Compliant: log_connections is set to on
    }

    backup_configuration {
      enabled = true
      start_time = "03:00"
    }
  }
}
