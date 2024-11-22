provider "google" {
  alias   = "pass_google"
  project = "my-project"
  region  = "us-central1"
}

# Create PostgreSQL instance with correct log_min_error_statement setting
resource "google_sql_database_instance" "pass_postgres" {
  provider         = google.pass_google
  name             = "pass-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "log_min_error_statement"
      value = "ERROR" # Compliant setting
    }

    backup_configuration {
      enabled    = true
      start_time = "03:00"
    }

    ip_configuration {
    }
  }

  deletion_protection = true
}
