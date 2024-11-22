provider "google" {
  alias   = "fail_google"
  project = "my-project"
  region  = "us-central1"
}

resource "google_sql_database_instance" "fail_instance" {
  provider         = google.fail_google
  name             = "fail-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "log_error_verbosity"
      value = "TERSE" # Non-compliant setting
    }
  }

  deletion_protection = false
}
