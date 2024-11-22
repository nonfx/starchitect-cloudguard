provider "google" {
  alias   = "fail_gcp"
  project = "my-project-id"
  region  = "us-central1"
}

# Create SQL Server instance without trace flag 3625 (non-compliant)
resource "google_sql_database_instance" "fail_instance" {
  provider = google.fail_gcp
  name     = "fail-sql-instance"
  database_version = "SQLSERVER_2017_STANDARD"
  region   = "us-central1"

  settings {
    tier = "db-custom-2-3840"
    
    database_flags {
      name  = "cross db ownership chaining"
      value = "off"
    }
  }

  deletion_protection = false
}
