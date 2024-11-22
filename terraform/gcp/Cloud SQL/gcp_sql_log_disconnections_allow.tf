resource "google_sql_database_instance" "pass_instance" {
  name             = "pass-postgres-instance"
  database_version = "POSTGRES_14"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    # Compliant: log_disconnections is enabled
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }

    # Additional security configurations
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }

    ip_configuration {
    }
  }

  deletion_protection = true
}
