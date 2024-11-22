# Instance without Confidential Computing enabled
resource "google_compute_instance" "fail_instance" {
  name         = "fail-instance"
  machine_type = "n2d-standard-2"  # AMD EPYC CPU required
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  network_interface {
    network = "default"
  }
}
