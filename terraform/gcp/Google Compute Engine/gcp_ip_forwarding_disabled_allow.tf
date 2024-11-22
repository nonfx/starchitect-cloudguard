resource "google_compute_instance" "pass_instance" {
  name         = "pass-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  # can_ip_forward defaults to false (compliant)

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  network_interface {
    network = "default"
  }
}
