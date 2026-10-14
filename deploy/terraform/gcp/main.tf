# One VM that builds and runs deploy/compose.yaml, reachable only from your
# address, with the GitHub token and the login hash read from Secret Manager
# at the moment they are needed.

# --- APIs ---------------------------------------------------------------------

resource "google_project_service" "apis" {
  for_each           = toset(["compute.googleapis.com", "secretmanager.googleapis.com", "iap.googleapis.com"])
  service            = each.key
  disable_on_destroy = false
}

# --- network ------------------------------------------------------------------

resource "google_compute_network" "vpc" {
  name                    = "${var.name}-vpc"
  auto_create_subnetworks = false
  depends_on              = [google_project_service.apis]
}

resource "google_compute_subnetwork" "subnet" {
  name                     = "${var.name}-subnet"
  network                  = google_compute_network.vpc.id
  region                   = var.region
  ip_cidr_range            = "10.10.0.0/24"
  private_ip_google_access = true
}

# Inbound: the web interface from your address only.
resource "google_compute_firewall" "web_in" {
  name          = "${var.name}-web-in"
  network       = google_compute_network.vpc.id
  direction     = "INGRESS"
  source_ranges = var.allowed_cidrs
  target_tags   = [var.name]
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

# Inbound: SSH only through Identity-Aware Proxy (Google's published range),
# so port 22 is never open to the internet.
resource "google_compute_firewall" "ssh_iap_in" {
  name          = "${var.name}-ssh-iap-in"
  network       = google_compute_network.vpc.id
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]
  target_tags   = [var.name]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

# Outbound: only what scanning needs, by port. GitHub, the vulnerability
# databases, the exploitation feeds, package and image registries are all
# HTTPS (a few mirrors are HTTP); DNS for resolving them. Everything else is
# denied. Restricting by destination NAME needs Cloud NGFW Enterprise, a paid
# add-on; DEPLOY.md says so.
resource "google_compute_firewall" "egress_allow" {
  name               = "${var.name}-egress-allow"
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [var.name]
  allow {
    protocol = "tcp"
    ports    = ["80", "443", "53"]
  }
  allow {
    protocol = "udp"
    ports    = ["53"]
  }
}

resource "google_compute_firewall" "egress_deny" {
  name               = "${var.name}-egress-deny"
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 65000
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [var.name]
  deny {
    protocol = "all"
  }
}

resource "google_compute_address" "ip" {
  name       = "${var.name}-ip"
  region     = var.region
  depends_on = [google_project_service.apis]
}

# --- identity -----------------------------------------------------------------

# The VM's own identity. It can read exactly two secrets and write logs and
# metrics; no key file is ever created for it.
resource "google_service_account" "vm" {
  account_id   = "${var.name}-vm"
  display_name = "vulnframework VM"
}

data "google_secret_manager_secret" "github_token" {
  secret_id  = var.github_token_secret
  depends_on = [google_project_service.apis]
}

data "google_secret_manager_secret" "login_hash" {
  secret_id  = var.login_hash_secret
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_iam_member" "github_token" {
  secret_id = data.google_secret_manager_secret.github_token.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_secret_manager_secret_iam_member" "login_hash" {
  secret_id = data.google_secret_manager_secret.login_hash.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_project_iam_member" "logs" {
  for_each = toset(["roles/logging.logWriter", "roles/monitoring.metricWriter"])
  project  = var.project_id
  role     = each.key
  member   = "serviceAccount:${google_service_account.vm.email}"
}

# --- backups ------------------------------------------------------------------

# Daily snapshots of the boot disk, which holds the database volume. Restore
# is DEPLOY.md's "Restore from a snapshot".
resource "google_compute_resource_policy" "snapshots" {
  name   = "${var.name}-daily"
  region = var.region
  snapshot_schedule_policy {
    schedule {
      daily_schedule {
        days_in_cycle = 1
        start_time    = "04:00"
      }
    }
    retention_policy {
      max_retention_days    = var.snapshot_retention_days
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }
  }
  depends_on = [google_project_service.apis]
}

# --- the VM -------------------------------------------------------------------

resource "google_compute_instance" "vm" {
  name         = var.name
  machine_type = var.machine_type
  zone         = var.zone
  tags         = [var.name]

  boot_disk {
    # Encrypted at rest with Google-managed keys, as every Compute Engine
    # disk is. The repositories being scanned live here only while scanned.
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = var.disk_size_gb
      type  = "pd-balanced"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.subnet.id
    access_config {
      nat_ip = google_compute_address.ip.address
    }
  }

  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    startup-script = templatefile("${path.module}/startup.sh.tftpl", {
      project_id          = var.project_id
      site_address        = google_compute_address.ip.address
      tls                 = var.tls
      login_user          = var.login_user
      github_token_secret = var.github_token_secret
      login_hash_secret   = var.login_hash_secret
      repo_url            = var.repo_url
      repo_ref            = var.repo_ref
      sweep_schedule      = var.sweep_schedule
      sweep_concurrency   = var.sweep_concurrency
    })
  }

  depends_on = [
    google_secret_manager_secret_iam_member.github_token,
    google_secret_manager_secret_iam_member.login_hash,
  ]
}

resource "google_compute_disk_resource_policy_attachment" "snapshots" {
  name = google_compute_resource_policy.snapshots.name
  disk = google_compute_instance.vm.name
  zone = var.zone
}
