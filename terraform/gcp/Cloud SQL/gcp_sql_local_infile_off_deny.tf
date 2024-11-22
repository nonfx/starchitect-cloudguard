provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

resource "google_sql_database_instance" "fail_instance" {
  provider = google.fail_google
  name             = "fail-mysql-instance"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
    
    database_flags {
      name  = "local_infile"
      value = "on"  # Non-compliant: local_infile is enabled
    }

    ip_configuration {
      ipv4_enabled = true
    }
  }

  deletion_protection = false
}