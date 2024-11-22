provider "google" {
  alias   = "pass_aws"
  project = "my-project"
  region  = "us-central1"
}

resource "google_sql_database_instance" "pass_postgres" {
  provider         = google.pass_aws
  name             = "pass-postgres-instance"
  database_version = "POSTGRES_13"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "log_min_messages"
      value = "WARNING" # Compliant: Set to WARNING level
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
