provider "google" {
  alias = "fail_google"
  project = "my-project"
  region  = "us-central1"
}

# Create PostgreSQL instance with incorrect log_min_error_statement setting
resource "google_sql_database_instance" "fail_postgres" {
  provider = google.fail_google
  name             = "fail-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "log_min_error_statement"
      value = "INFO"  # Non-compliant setting
    }
  }

  deletion_protection = false
}
