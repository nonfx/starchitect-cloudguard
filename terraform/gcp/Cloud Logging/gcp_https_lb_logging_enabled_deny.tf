provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create backend service without logging enabled
resource "google_compute_backend_service" "fail_backend" {
  name        = "fail-backend-service"
  protocol    = "HTTPS"
  timeout_sec = 10

  health_checks = [google_compute_health_check.fail_health_check.id]

  # Logging configuration that will fail the test
  log_config {
    enable = false
    sample_rate = 0.0
  }
}

# Required health check for the backend service
resource "google_compute_health_check" "fail_health_check" {
  name               = "fail-health-check"
  check_interval_sec = 1
  timeout_sec        = 1

  tcp_health_check {
    port = "80"
  }
}