provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

resource "google_sql_database_instance" "pass_instance" {
  provider = google.pass_google
  name             = "pass-mysql-instance"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
    
    database_flags {
      name  = "local_infile"
      value = "off"  # Compliant: local_infile is disabled
    }

    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        name  = "internal"
        value = "10.0.0.0/8"
      }
    }

    backup_configuration {
      enabled = true
      binary_log_enabled = true
    }
  }

  deletion_protection = true
}