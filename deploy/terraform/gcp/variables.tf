variable "project_id" {
  description = "The GCP project to deploy into. It must already exist, with billing enabled."
  type        = string
}

variable "region" {
  description = "Region for the VM and its static address."
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "Zone for the VM."
  type        = string
  default     = "us-central1-a"
}

variable "name" {
  description = "Prefix for every resource this creates."
  type        = string
  default     = "vulnframework"
}

variable "machine_type" {
  description = "VM size. Scanners are CPU- and memory-hungry; e2-standard-4 (4 vCPU, 16 GB) scans a handful of repositories at a time."
  type        = string
  default     = "e2-standard-4"
}

variable "disk_size_gb" {
  description = "Boot disk size. Holds the images (the scanner image is several GB), the database, and each repository while it is scanned."
  type        = number
  default     = 100
}

variable "allowed_cidrs" {
  description = "Who may reach the web interface: your own address as a /32 (curl -s https://ifconfig.me). No default, on purpose: the interface must never be open to the internet by accident."
  type        = list(string)

  validation {
    condition     = length(var.allowed_cidrs) > 0 && !contains(var.allowed_cidrs, "0.0.0.0/0")
    error_message = "Set allowed_cidrs to your own address(es). 0.0.0.0/0 is refused: the login is a single password."
  }
}

variable "tls" {
  description = "\"internal\": Caddy's own certificate (a browser warning, works with allowed_cidrs limited to you). An e-mail address: Let's Encrypt, which needs ports 80/443 reachable from the internet while issuing, so it also needs allowed_cidrs widened, which this module refuses."
  type        = string
  default     = "internal"
}

variable "login_user" {
  description = "The interface's one login name."
  type        = string
  default     = "admin"
}

variable "github_token_secret" {
  description = "Secret Manager secret holding the read-only GitHub token. Create it yourself before apply (DEPLOY.md step 4); this module never sees the token, so it is not in Terraform state."
  type        = string
  default     = "vulnframework-github-token"
}

variable "login_hash_secret" {
  description = "Secret Manager secret holding the login's bcrypt hash. Created by you, like the token."
  type        = string
  default     = "vulnframework-login-hash"
}

variable "repo_url" {
  description = "Where the VM fetches this project's source. Empty: you copy it to /opt/vulnframework yourself (DEPLOY.md shows how)."
  type        = string
  default     = "https://github.com/pobtampal/vulnerabilityAI.git"
}

variable "repo_ref" {
  description = "Branch or tag of repo_url to deploy."
  type        = string
  default     = "real-repos"
}

variable "sweep_schedule" {
  description = "When the daily sweep runs, as a systemd OnCalendar expression (UTC)."
  type        = string
  default     = "*-*-* 03:00:00"
}

variable "sweep_concurrency" {
  description = "How many repositories a sweep scans at once."
  type        = number
  default     = 2
}

variable "snapshot_retention_days" {
  description = "How long daily disk snapshots (the database's backup) are kept."
  type        = number
  default     = 7
}
