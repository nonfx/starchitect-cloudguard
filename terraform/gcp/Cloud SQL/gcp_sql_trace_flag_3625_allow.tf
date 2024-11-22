provider "google" {
  alias   = "pass_gcp"
  project = "my-project-id"
  region  = "us-central1"
}

# Create SQL Server instance with trace flag 3625 enabled (compliant)
resource "google_sql_database_instance" "pass_instance" {
  provider = google.pass_gcp
  name     = "pass-sql-instance"
  database_version = "SQLSERVER_2017_STANDARD"
  region   = "us-central1"

  settings {
    tier = "db-custom-2-3840"
    
    database_flags {
      name  = "3625"
      value = "on"
    }

    database_flags {
      name  = "cross db ownership chaining"
      value = "off"
    }
  }

  deletion_protection = false
}
