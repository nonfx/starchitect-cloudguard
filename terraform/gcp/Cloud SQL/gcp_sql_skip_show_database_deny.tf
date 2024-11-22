# Configure the Google Provider with failing configuration
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create a Cloud SQL instance with skip_show_database set to off (failing case)
resource "google_sql_database_instance" "fail_instance" {
  name             = "fail-mysql-instance"
  database_version = "MYSQL_8_0"
  region           = "us-central1"

  settings {
    tier = "db-f1-micro"
    
    # Database flag set incorrectly to off
    database_flags {
      name  = "skip_show_database"
      value = "off"
    }

    ip_configuration {
      ipv4_enabled = true
    }
  }

  deletion_protection = false
}
