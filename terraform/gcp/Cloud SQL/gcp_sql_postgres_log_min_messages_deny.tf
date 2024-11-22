provider "google" {
  alias = "fail_aws"
  project = "my-project"
  region  = "us-central1"
}

resource "google_sql_database_instance" "fail_postgres" {
  provider = google.fail_aws
  name             = "fail-postgres-instance"
  database_version = "POSTGRES_13"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    database_flags {
      name  = "log_min_messages"
      value = "DEBUG1"  # Non-compliant: Set below WARNING level
    }
  }

  deletion_protection = false
}
