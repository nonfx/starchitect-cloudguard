provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create SQL Server instance with cross db ownership chaining disabled (compliant)
resource "google_sql_database_instance" "pass_instance" {
  provider = google.pass_google
  name             = "pass-sql-instance"
  database_version = "SQLSERVER_2017_STANDARD"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-3840"
    
    database_flags {
      name  = "cross db ownership chaining"
      value = "off"  # Compliant setting
    }
  }

  deletion_protection = false
}
