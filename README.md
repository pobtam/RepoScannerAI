# Automated vulnerability detection and remediation framework

This project finds security problems in a set of code repositories, decides
which ones matter, opens pull requests to fix the ones it safely can, and
reports honestly on everything it could not do.

The last part is the point. Most tools of this kind produce a number. This one
is built so that **a number is never shown without saying what it rests on** —
what was scanned, what was not, what was measured, what nobody looked at, and
which figures are provisional.

---

## Try it in two commands

You need two pieces of free software installed: **Go** and **Node.js**. The
setup script checks for both and tells you where to get them if they are
missing.

```
./setup.sh
./run.sh
```

Then open **http://localhost:5173** in your browser.

That is all. No database, no Docker, no accounts, no API keys, no internet
connection needed after setup, and nothing leaves your machine.

**What you will be looking at is demonstration data.** Every repository,
vulnerability and credential in it is invented, and every screen says so. It
exists so you can see how the system behaves without pointing it at anything
real.

* `SETUP.md` — installing the two prerequisites, step by step.
* `USAGE.md` — what each screen shows and how to read it.
* `FINAL-STATUS.md` — **what is real and what is not**, and exactly what stands
  between this and a production deployment. Read this before drawing any
  conclusion about what the system can do today.
* `DECISIONS-NEEDED.md` — the decisions that are not the author's to make.

---

## What it does, in order

1. **Scans** each repository with several tools — dependency advisories,
   static analysis, secret detection, configuration checks — and records what
   each tool said, including which tools failed.
2. **Merges** what the tools reported, so one vulnerability found by three
   tools is one finding rather than three.
3. **Enriches** each finding with exploitation intelligence: is this being
   exploited in the wild, and how likely is it to be.
4. **Explains** each finding in plain language using a language model, which
   writes the narrative and never decides the priority.
5. **Scores** each finding deterministically from severity, exploitation,
   reachability, dependency type and how important the repository is.
6. **Decides** what to do with each one from a written policy table: fix it
   automatically, open a ticket, escalate, or wait for an upstream fix.
7. **Fixes** what it safely can — a dependency bump, or a source change made
   by an agent — and proves the fix with a re-scan before opening a pull
   request. It never merges its own work.
8. **Verifies** by re-scanning: a finding is only resolved when a successful
   scan no longer sees it. A merged pull request is not proof.
9. **Reports** each run as an immutable, content-hashed document, so a figure
   quoted in a meeting can be traced back to the exact run it came from.

## What it refuses to do

These are deliberate, and each one exists because the alternative is worse:

* **It never merges its own pull requests.** A human reviews every change.
* **It never treats an absence as a fix.** If a repository failed to scan, its
  findings do not disappear — they are marked as not re-observed, with the
  reason, because "we did not look" and "it is gone" are different facts.
* **It never stores, prints or transmits a credential.** A secret finding
  records the *kind* of credential and where it is, and has nowhere to put the
  value. Three independent layers check that, and the interface refuses to
  render a response that contains one.
* **It never shows an unqualified number.** A priority computed without
  exploitation data says so, next to the number. A breach count measured
  against unreviewed windows says so, next to the number.
* **It never lets the agent hold a credential, reach the network, or write
  outside its clone.** Those are enforced by the harness that runs it, not
  requested of it.

## Layout

```
vulnframework/     the backend: scanners, store, policy, remediation, reports, API
reportui/          the web interface, built against the API's generated schema
prototype/         the original interaction sketch the specification was written against
*.md               the specifications, and the documents listed above
```
