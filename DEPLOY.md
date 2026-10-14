# Deploying to Google Cloud (minimum demo)

This puts the scanner on one Google Cloud VM. A read-only GitHub token
discovers every repository your account reaches. A daily sweep downloads,
scans and deletes each one. You browse the results over HTTPS, behind a
login, from your own IP address only.

Nothing here writes to GitHub. The scanner sends only GET requests, and the
token you create can only read.

```
 your browser ──HTTPS + login──►  Caddy (web) ──► API ──► Postgres
   (your IP only)                     │                      ▲
                                      │              sweep (daily timer)
                                      │                      │
                                  built UI        GitHub (read-only token,
                                                  from Secret Manager)
```

**What this is not yet:** a multi-user service. There is one login, using
HTTP basic auth over HTTPS. There is no identity provider, there are no
roles, and nothing can be changed from the web pages. The firewall limiting
access to your IP is part of the security, not an extra. See "Limits" at the
end.

---

## 0. What you need

- A Google Cloud project with billing enabled, and its **project ID**.
- On your machine:
  - `gcloud`, the Google Cloud CLI.
  - `terraform` 1.6 or newer. If you don't have it, Docker works:
    `alias terraform='docker run --rm -it -v "$PWD:/w" -w /w -v "$HOME/.config/gcloud:/root/.config/gcloud" hashicorp/terraform:1.9.8'`
  - Docker, only to compute the login hash in step 4.
- A GitHub account whose repositories you want scanned.

## 1. Get the code where the VM can fetch it

The VM clones `https://github.com/pobtampal/vulnerabilityAI.git` at branch
`real-repos`. That only works once the branch is pushed, and the repository
is public.

- **Pushing:** older commits contain the fake test keys, so GitHub push
  protection blocks the push. Allow them once with the two unblock links from
  the first push attempt (they are recorded in PROGRESS.md), then push:
  ```sh
  git push -u origin main real-repos
  ```
- **If the repository is private, or you'd rather not push:** set
  `repo_url = ""` in step 5 and copy the code to the VM after it boots (see
  "Copying the code instead" below).

## 2. Sign in to Google Cloud

```sh
gcloud auth login
gcloud auth application-default login       # what Terraform uses
gcloud config set project YOUR_PROJECT_ID
gcloud services enable secretmanager.googleapis.com compute.googleapis.com iap.googleapis.com
```

## 3. Create the GitHub token

On GitHub go to **Settings → Developer settings → Personal access tokens →
Fine-grained tokens → Generate new token**:

| Setting | Value |
|---|---|
| Expiration | 30 or 90 days (the interface warns you 14 days before expiry) |
| Resource owner | your account, or an organisation you belong to |
| Repository access | **All repositories**, or only the ones to scan |
| Permissions → Repository | **Contents: Read-only**, **Metadata: Read-only**. Nothing else. |

Copy the token. A **classic** token is refused if it grants any write scope.
There's no read-only classic scope for private code, which is why a
fine-grained token is required.

A fine-grained token can reach repositories of **one** resource owner. Repos
in an organisation where you are only a collaborator may need the
organisation to approve the token. Collaborator repos are skipped by default
anyway.

## 4. Put the two secrets in Secret Manager

Neither value goes into Terraform. The VM reads them itself, at the moment it
needs them.

```sh
# The GitHub token (paste it when prompted; it is not echoed or saved to history)
read -rs GH_TOKEN && printf %s "$GH_TOKEN" | \
  gcloud secrets create vulnframework-github-token --replication-policy=automatic --data-file=- && unset GH_TOKEN

# The login: choose a long password, keep it in your password manager, and store only its hash
read -rs LOGIN_PW && docker run --rm caddy:2.8.4-alpine caddy hash-password --plaintext "$LOGIN_PW" | tr -d '\n' | \
  gcloud secrets create vulnframework-login-hash --replication-policy=automatic --data-file=- && unset LOGIN_PW
```

The login name is `admin`, unless you set `login_user` in step 5.

## 5. Configure and create the VM

```sh
cd deploy/terraform/gcp
cp terraform.tfvars.example terraform.tfvars
curl -s https://ifconfig.me; echo           # your address, for allowed_cidrs
$EDITOR terraform.tfvars                    # project_id, allowed_cidrs = ["YOUR.IP/32"]
terraform init
terraform plan                              # read it: about 15 resources, no deletions
terraform apply
```

The outputs give the URL and ready-made commands.

## 6. Wait for the first boot (15–30 minutes)

The first boot installs Docker, fetches the code, and builds the images. The
scanner image is most of that time. To follow it:

```sh
$(terraform output -raw startup_log)
```

It ends with `=== ready: https://<ip>`.

## 7. Open it

Open the `url` output (`https://<ip>`). With the default `tls = "internal"`
the browser warns about the certificate; accept it once. Log in as `admin`
with your password.

The pages are empty until the first sweep. The **GitHub** page fills in after
it runs.

## 8. Run the first sweep now

The timer runs a sweep every day at 03:00 UTC. To run one now:

```sh
$(terraform output -raw sweep_now)
# follow it:
gcloud compute ssh vulnframework --zone us-central1-a --tunnel-through-iap -- \
  sudo journalctl -u vulnframework-sweep.service -f
```

A sweep:
1. Lists every repository the token reaches. Each one is scanned, or skipped
   with a reason: archived, fork, empty, too large, collaborator only, or
   excluded by you.
2. Downloads each scanned repository, scans it, and deletes it.
3. Scores and routes the findings. Routing stops at the decision: no tickets,
   no pull requests.

Expect a few minutes per repository. Each run's record is saved on the VM in
`/opt/vulnframework/deploy/runs/`.

---

## Day to day

| Task | How |
|---|---|
| Exclude a repository | On the VM: `cd /opt/vulnframework && sudo deploy/vfctl.sh repo exclude owner/name -reason "why"`. It is archived at once and skipped by later discoveries; `repo include owner/name` undoes it. |
| Check the connection | `sudo deploy/vfctl.sh github status` (account, token expiry, last discovery). |
| Secrets awaiting a person | `sudo deploy/vfctl.sh finding pending`, then `finding confirm-suppression`, `reject-suppression` or `confirm-rotation`. |
| See what was discovered | The **GitHub** page. |
| Rotate the GitHub token | Create a new token (step 3), then `printf %s "$NEW" \| gcloud secrets versions add vulnframework-github-token --data-file=-`. The next sweep uses it; nothing restarts. |
| Change the password | Add a new version of `vulnframework-login-hash` (step 4), then on the VM: `sudo rm /opt/vulnframework/deploy/.env && sudo reboot`. The startup script rewrites `.env`. The database password is regenerated too, which is fine on a fresh VM; on one with data, edit `LOGIN_HASH` in `.env` instead, then run `sudo docker compose -f deploy/compose.yaml up -d web`. |
| Update the code | On the VM: `cd /opt/vulnframework && sudo git pull && sudo deploy/build.sh && sudo docker compose -f deploy/compose.yaml up -d`. |
| Turn on AI explanations | Not wired into the VM in this minimum version. See "Limits". |

## Restore from a snapshot

Disk snapshots are taken daily at 04:00 UTC and kept for 7 days. They hold
the whole boot disk, including the database. To roll back:

```sh
gcloud compute snapshots list --filter="sourceDisk~vulnframework"
gcloud compute instances stop vulnframework --zone us-central1-a
gcloud compute disks create vulnframework-restored --zone us-central1-a --source-snapshot SNAPSHOT_NAME
gcloud compute instances detach-disk vulnframework --zone us-central1-a --disk vulnframework
gcloud compute instances attach-disk vulnframework --zone us-central1-a --disk vulnframework-restored --boot
gcloud compute instances start vulnframework --zone us-central1-a
```

Terraform will then show drift on the boot disk. Either keep it that way
(`terraform apply` would recreate the VM), or import the restored disk.

## Copying the code instead

If `repo_url = ""`, or the clone failed (private or unpushed repository), the
startup log says so and stops. From your machine:

```sh
git bundle create /tmp/vf.bundle real-repos
gcloud compute scp /tmp/vf.bundle vulnframework:/tmp/ --zone us-central1-a --tunnel-through-iap
gcloud compute ssh vulnframework --zone us-central1-a --tunnel-through-iap -- \
  'sudo git clone -b real-repos /tmp/vf.bundle /opt/vulnframework && sudo reboot'
```

---

## What it costs

These are approximate us-central1 on-demand list prices as I know them.
Check the [pricing calculator](https://cloud.google.com/products/calculator)
before relying on them.

| Item | Approx. |
|---|---|
| e2-standard-4 VM, running | ~US$0.13/hour, ~US$98/month |
| 100 GB balanced disk | ~US$10/month |
| Static external IP, in use | ~US$3.65/month |
| Snapshots (changed blocks only) | a few US$/month |
| Secret Manager (2 secrets) | well under US$1/month |
| **Left running** | **roughly US$110–120/month, ~US$4/day** |

To pause, stop the VM:
`gcloud compute instances stop vulnframework --zone us-central1-a`. The disk
and IP still cost about US$15/month while it's stopped. Start it again with
`... start ...`; the stack and the timer come back on their own.

## Tear it all down

```sh
cd deploy/terraform/gcp
terraform destroy
# Snapshots outlive the disk on purpose; delete them when you're sure:
gcloud compute snapshots list --filter="sourceDisk~vulnframework" --format="value(name)" | \
  xargs -r gcloud compute snapshots delete --quiet
gcloud secrets delete vulnframework-github-token --quiet
gcloud secrets delete vulnframework-login-hash --quiet
```

Then revoke the token on GitHub (Settings → Developer settings → Fine-grained
tokens → Delete). Deleting the secret doesn't revoke it.

---

## Security, briefly

- **The token** lives only in Secret Manager. It's read at the start of each
  sweep and passed to the sweep container by name. It's never written to
  disk or stored in the database, and never appears in logs, the API or the
  pages.
- **Read-only** is enforced twice: by the token's own permissions, and by the
  scanner's GitHub client, which refuses any request but GET or HEAD before it
  leaves the VM.
- **The interface** can be reached only from `allowed_cidrs`, only over
  HTTPS, and only with the login. The API isn't published at all: the proxy
  deletes any identity headers a browser sends and sets its own.
- **SSH** works only through Identity-Aware Proxy. Port 22 isn't open to the
  internet.
- **Outbound traffic** is limited to ports 80, 443 and 53. Limiting it to
  named destinations (GitHub, osv.dev and so on) needs Cloud NGFW Enterprise,
  a paid add-on, so it isn't done here.
- **Private code** is on the disk only while it's being scanned. The disk is
  encrypted at rest, as every Compute Engine disk is.

## Limits (what the full plan adds later)

- **One login, no roles** (Phase 4 adds OpenID Connect sign-in, roles, and
  two-factor). Until then, don't widen `allowed_cidrs`.
- **No web-based changes.** Excluding repositories and confirming secrets are
  `vfctl` commands on the VM.
- **AI triage is off.** Turning it on means adding an Anthropic key secret and
  the `-triage-model` flag to the sweep. It sends finding metadata, not code.
- **Languages:** Go and JavaScript repositories are scanned fully. Others get
  secret, configuration and container scanning only, until Phase 1
  (mixed-language scanning) lands.
- **Let's Encrypt** (`tls = "you@example.com"`) needs ports 80/443 open to
  the internet while the certificate is issued. This module refuses
  `0.0.0.0/0`, so the default is Caddy's own certificate and a browser
  warning.
- **No health page or alerts yet** (Phase 5/6). Check sweeps with `journalctl`
  as in step 8.
