provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create SQL Server instance with cross db ownership chaining enabled (non-compliant)
resource "google_sql_database_instance" "fail_instance" {
  provider = google.fail_google
  name             = "fail-sql-instance"
  database_version = "SQLSERVER_2017_STANDARD"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-3840"
    
    database_flags {
      name  = "cross db ownership chaining"
      value = "on"  # Non-compliant setting
    }
  }

  deletion_protection = false
}
