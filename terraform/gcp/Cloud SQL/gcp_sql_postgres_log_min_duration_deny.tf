provider "google" {
  alias = "fail_gcp"
  project = "my-project"
  region  = "us-central1"
}

resource "google_sql_database_instance" "fail_postgres" {
  provider = google.fail_gcp
  name             = "fail-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
    
    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"  # Non-compliant: Set to log statements taking over 1000ms
    }
  }

  deletion_protection = false
}
