data "google_compute_image" "default" {
  # https://cloud.google.com/compute/docs/images
  family  = "ubuntu-minimal-2004-lts"
  project = "ubuntu-os-cloud"
}

resource "google_compute_instance" "default" {
  name = "test-${var.TEST_RUN_ID}"
  // NOTE: e2 instance type is required to collect instance/memory/balloon/* 
  // metrics, available only on those instances.
  // https://cloud.google.com/monitoring/api/metrics_gcp
  machine_type = "e2-micro"
  zone         = var.zone

  labels = {
    team         = "integrations"
    run_id       = var.TEST_RUN_ID
    repo         = var.repo_name
    pull_request = var.pull_request
    ci_build     = var.ci_build_number
  }

  boot_disk {
    initialize_params {
      image = data.google_compute_image.default.self_link
    }
  }

  network_interface {
    network = "default"

    access_config {
      // Ephemeral public IP
    }
  }
}
