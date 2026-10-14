# Google Cloud only. Everything provider-specific lives in this directory;
# the stack it runs (deploy/compose.yaml) knows nothing about any cloud.
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.8"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
