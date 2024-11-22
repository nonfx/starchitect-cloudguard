provider "google" {
  alias   = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create SQL Server instance with limiting user connections (non-compliant)
resource "google_sql_database_instance" "fail_instance" {
  provider = google.fail_google
  name     = "fail-sql-instance"
  region   = "us-central1"
  database_version = "SQLSERVER_2019_STANDARD"

  settings {
    tier = "db-custom-2-3840"
    
    database_flags {
      name  = "user connections"
      value = "100"  # Artificially limiting connections
    }
  }

  deletion_protection = false
}
