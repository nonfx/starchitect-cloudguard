provider "google" {
  alias   = "fail_gcp"
  project = "my-project-id"
  region  = "us-central1"
}

# Create SQL Server instance without remote access disabled (non-compliant)
resource "google_sql_database_instance" "fail_instance" {
  provider = google.fail_gcp
  name     = "fail-sql-instance"
  region   = "us-central1"
  database_version = "SQLSERVER_2017_STANDARD"

  settings {
    tier = "db-custom-2-3840"
    
    database_flags {
      name  = "remote access"
      value = "on"  # Non-compliant: remote access is enabled
    }
  }

  deletion_protection = false
}