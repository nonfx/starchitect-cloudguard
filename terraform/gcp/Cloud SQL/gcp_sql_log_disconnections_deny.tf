resource "google_sql_database_instance" "fail_instance" {
  name             = "fail-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
    
    # Non-compliant: log_disconnections is disabled
    database_flags {
      name  = "log_disconnections"
      value = "off"
    }
  }

  deletion_protection = false
}