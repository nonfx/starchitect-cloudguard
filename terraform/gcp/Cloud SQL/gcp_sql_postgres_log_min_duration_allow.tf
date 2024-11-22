provider "google" {
  alias   = "pass_gcp"
  project = "my-project"
  region  = "us-central1"
}

resource "google_sql_database_instance" "pass_postgres" {
  provider         = google.pass_gcp
  name             = "pass-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "log_min_duration_statement"
      value = "-1" # Compliant: Logging of statement duration is disabled
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
