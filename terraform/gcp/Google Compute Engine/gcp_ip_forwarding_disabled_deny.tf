resource "google_compute_instance" "fail_instance" {
  name         = "fail-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  can_ip_forward = true  # Non-compliant: IP forwarding enabled

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  network_interface {
    network = "default"
  }
}
