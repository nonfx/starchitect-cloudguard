provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create backend service with logging enabled
resource "google_compute_backend_service" "pass_backend" {
  name        = "pass-backend-service"
  protocol    = "HTTPS"
  timeout_sec = 10

  health_checks = [google_compute_health_check.pass_health_check.id]

  # Logging configuration that will pass the test
  log_config {
    enable = true
    sample_rate = 1.0
  }
}

# Required health check for the backend service
resource "google_compute_health_check" "pass_health_check" {
  name               = "pass-health-check"
  check_interval_sec = 1
  timeout_sec        = 1

  tcp_health_check {
    port = "80"
  }
}