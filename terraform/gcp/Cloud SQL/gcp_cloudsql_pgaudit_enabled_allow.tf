provider "google" {
  alias = "pass_gcp"
  project = "my-project"
  region  = "us-central1"
}

# Create PostgreSQL instance with pgaudit enabled
resource "google_sql_database_instance" "pass_instance" {
  provider = google.pass_gcp
  name             = "pass-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
    
    database_flags {
      name  = "cloudsql.enable_pgaudit"
      value = "on"
    }
    
    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }
  }

  deletion_protection = false
}
