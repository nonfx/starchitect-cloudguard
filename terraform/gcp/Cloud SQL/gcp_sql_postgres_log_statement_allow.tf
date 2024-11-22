provider "google" {
  project = "my-project"
  region  = "us-central1"
}

resource "google_sql_database_instance" "pass_postgres" {
  name             = "pass-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "log_statement"
      value = "ddl" # Compliant setting
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
