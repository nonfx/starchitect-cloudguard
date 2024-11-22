provider "google" {
  project = "my-project"
  region  = "us-central1"
}

resource "google_sql_database_instance" "fail_postgres" {
  name             = "fail-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "log_statement"
      value = "none"  # Non-compliant setting
    }
  }

  deletion_protection = false
}
