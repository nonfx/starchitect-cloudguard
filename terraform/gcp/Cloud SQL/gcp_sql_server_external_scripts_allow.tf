provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create SQL Server instance with external scripts disabled (compliant)
resource "google_sql_database_instance" "pass_instance" {
  provider = google.pass_google
  name             = "pass-sql-instance"
  region           = "us-central1"
  database_version = "SQLSERVER_2019_STANDARD"

  settings {
    tier = "db-custom-2-3840"
    
    database_flags {
      name  = "external scripts enabled"
      value = "off"  # Compliant setting
    }
  }

  deletion_protection = false
}
