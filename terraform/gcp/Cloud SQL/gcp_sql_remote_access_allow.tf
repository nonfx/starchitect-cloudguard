provider "google" {
  alias   = "pass_gcp"
  project = "my-project-id"
  region  = "us-central1"
}

# Create SQL Server instance with remote access disabled (compliant)
resource "google_sql_database_instance" "pass_instance" {
  provider = google.pass_gcp
  name     = "pass-sql-instance"
  region   = "us-central1"
  database_version = "SQLSERVER_2017_STANDARD"

  settings {
    tier = "db-custom-2-3840"
    
    database_flags {
      name  = "remote access"
      value = "off"  # Compliant: remote access is disabled
    }
  }

  deletion_protection = false
}