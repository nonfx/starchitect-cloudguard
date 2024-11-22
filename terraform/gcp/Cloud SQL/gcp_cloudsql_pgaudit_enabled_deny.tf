provider "google" {
  alias = "fail_gcp"
  project = "my-project"
  region  = "us-central1"
}

# Create PostgreSQL instance without pgaudit enabled
resource "google_sql_database_instance" "fail_instance" {
  provider = google.fail_gcp
  name             = "fail-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
    
    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }
  }

  deletion_protection = false
}
