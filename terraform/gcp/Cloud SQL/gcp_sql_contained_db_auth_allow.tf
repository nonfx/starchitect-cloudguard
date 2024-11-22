provider "google" {
  alias = "pass_aws"
  project = "my-project-id"
  region  = "us-central1"
}

# Create SQL Server instance with contained database authentication disabled (compliant)
resource "google_sql_database_instance" "pass_instance" {
  provider = google.pass_aws
  name             = "pass-sql-instance"
  region           = "us-central1"
  database_version = "SQLSERVER_2019_STANDARD"

  settings {
    tier = "db-custom-2-3840"

    database_flags {
      name  = "contained database authentication"
      value = "off"  # Compliant setting
    }
  }

  deletion_protection = false
}
