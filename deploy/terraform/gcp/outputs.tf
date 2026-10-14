output "url" {
  description = "The interface. With tls = internal the browser warns about the certificate the first time."
  value       = "https://${google_compute_address.ip.address}"
}

output "ip" {
  description = "The VM's static address."
  value       = google_compute_address.ip.address
}

output "ssh" {
  description = "Shell on the VM, through Identity-Aware Proxy."
  value       = "gcloud compute ssh ${google_compute_instance.vm.name} --zone ${var.zone} --project ${var.project_id} --tunnel-through-iap"
}

output "startup_log" {
  description = "Follow the first boot's progress."
  value       = "gcloud compute ssh ${google_compute_instance.vm.name} --zone ${var.zone} --project ${var.project_id} --tunnel-through-iap -- sudo tail -f /var/log/vulnframework-startup.log"
}

output "sweep_now" {
  description = "Run a sweep immediately instead of waiting for the timer."
  value       = "gcloud compute ssh ${google_compute_instance.vm.name} --zone ${var.zone} --project ${var.project_id} --tunnel-through-iap -- sudo systemctl start vulnframework-sweep.service"
}
