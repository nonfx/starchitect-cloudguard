# Configure the Google Provider with passing configuration
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create a Cloud SQL instance with skip_show_database set to on (passing case)
resource "google_sql_database_instance" "pass_instance" {
  name             = "pass-mysql-instance"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"

    # Database flag correctly set to on
    database_flags {
      name  = "skip_show_database"
      value = "on"
    }

    # Additional security configurations
    backup_configuration {
      enabled            = true
      binary_log_enabled = true
    }

    ip_configuration {
      ipv4_enabled = true
    }
  }

  deletion_protection = true
}
