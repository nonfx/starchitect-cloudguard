provider "google" {
  alias   = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create SQL Server instance with non-limiting user connections (compliant)
resource "google_sql_database_instance" "pass_instance" {
  provider = google.pass_google
  name     = "pass-sql-instance"
  region   = "us-central1"
  database_version = "SQLSERVER_2019_STANDARD"

  settings {
    tier = "db-custom-2-3840"
    
    database_flags {
      name  = "user connections"
      value = "0"  # No artificial limit on connections
    }
  }

  deletion_protection = false
}
