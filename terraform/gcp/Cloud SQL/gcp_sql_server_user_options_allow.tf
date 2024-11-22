provider "google" {
  alias = "pass_google"
  project = "my-project"
  region  = "us-central1"
}

# Create SQL Server instance without user options flag (compliant)
resource "google_sql_database_instance" "pass_instance" {
  provider = google.pass_google
  name             = "pass-sql-instance"
  region           = "us-central1"
  database_version = "SQLSERVER_2019_STANDARD"

  settings {
    tier = "db-custom-2-3840"
    
    # No user options flag configured
    database_flags {
      name  = "cross db ownership chaining"
      value = "off"
    }
  }

  deletion_protection = false
}