# Using the interface

Open **http://localhost:5173** after running `./run.sh`.

Everything you see is **demonstration data**. The yellow strip at the top of
every page says so, and it also lists anything this deployment cannot do —
for example that the priority thresholds have not been calibrated. That strip
is not decoration: it tells you how much weight the numbers below it can bear.

---

## The banner at the top

Three kinds of thing appear there, and all three change what a number means:

* **DEMONSTRATION DATA** — nothing below came from a scanner.
* **Reading the *memory* backend** — where the data is stored.
* **Degraded in this deployment** — inputs the system does not have. A priority
  computed without exploitation data is narrower than one computed with it, and
  the number alone does not show that.

---

## Latest run

The first page. It answers "what happened in the most recent scan".

Read it in the order it is laid out, because the order is deliberate:

1. **Coverage first.** How much of the fleet was actually scanned. A repository
   nobody scanned is more urgent than a repository with findings, and this
   panel is above the counts so it cannot be skipped. If coverage is below
   100%, every number further down the page is lower than the truth rather
   than better.
2. **Findings.** The headline counts. Three separate figures that are never
   added together:
   * *unresolved* — still outstanding;
   * *pending verification* — a fix was merged and a scan has not yet confirmed
     it. Not resolved, not unresolved;
   * *resolved* — a successful scan no longer sees it.

   **Every count is a link.** Click it to see exactly the findings it counted.
   A number you cannot reproduce is a number you should not act on.
3. **Not fixed, by reason.** Why the outstanding ones are outstanding. "Tried
   and failed" and "nothing to do" are different states of the world and appear
   separately.
4. **Change since the previous run.** Compared with the previous run *of the
   same kind*. Note the row called **no longer observed** — it is deliberately
   not called "fixed", because a finding that stopped being seen may have been
   fixed or may simply not have been looked for.
5. **How this run was produced.** The scanner image, the tool versions, and how
   many of the five scoring inputs actually answered.

If the page says **"These figures are live, not a snapshot"**, the numbers are
today's state of those findings rather than the state as of that run. The
distinction matters for any run but the most recent.

---

## Findings

The main working view. It is a search over every finding ever recorded.

**The sentence under the title is the most important thing on the page.** It
reads something like:

> **17** matching, of **17** in this corpus (unresolved findings across all
> runs), of **18** ever recorded. This corpus excludes 1 records: verified,
> suppressed, declined and won't-fix findings…

Three numbers, kept apart: how many match your filter, how many are in the
corpus you chose, and how many exist at all. A single count would not tell you
which of those it was.

**The corpus selector** (top right) chooses what you are looking at:

* *unresolved across all runs* — the default, and the only safe default. It
  includes findings the most recent scan did not re-observe, which a
  "latest run" view would hide.
* *everything ever recorded* — including resolved and suppressed.
* *observed in one run* — the state of one run.

**Filters** are down the left. Every option shows how many results it would
return, and an option that would return nothing is greyed out rather than
hidden — so you can see that a category exists and is empty, instead of
wondering whether the filter is broken.

**The address bar holds your view.** Filters, sort order, corpus and page are
all in the URL, so you can copy the address and send someone exactly what you
are looking at.

### Reading a row

* **Priority** — P0 is most urgent. A ⚠ next to it means the figure rests on
  incomplete inputs; hover it to read what is missing.
* **Reachable** — one of three values, and the third is not the second:
  *reachable*, *not reachable*, or *unknown*. "Unknown" means nobody
  determined it. It is the common case and it is shown in italics so it cannot
  be mistaken for "not reachable".
* **Exploitation** — what the exploitation catalogues said. **"not checked"**
  and **"not looked up"** mean exactly that: nothing answered. They are not
  zero, and they are not reassurance.
* **SLA** — the remediation window, and how the finding stands against it. Age
  is never shown on its own, because the same age is unremarkable at one
  priority and a breach at another.
* **not re-observed** — the last applicable scan did not see it while it is
  still unresolved. Hover it: this is **ambiguous** between a fix and a
  coverage gap, and the coverage page is where you find out which.

Click any identifier to open the finding.

---

## A finding

Everything the system knows, and — just as importantly — everything it does
not. An absent value is shown as **—** with an explanation when you hover it,
rather than as a blank space or a zero.

* **Priority** is shown as an *argument*, not an assertion: the base score,
  each multiplier, and what each one was. If the recomputed band disagrees with
  the one recorded at the time, both are shown and the page says why.
* **Lifecycle** is every state change, with who made it and why.
* **Observations** is every run, *including the runs that did not see this
  finding*, and whether those runs' scans qualified. A run that failed says
  nothing about the finding, and the table says so.
* **Remediation attempts** is every attempt, not just the current one, so two
  earlier declined attempts are visible.

For a secret finding you will see the *kind* of credential and the file it is
in. You will never see the credential. There is nowhere in the system for it to
live.

---

## Coverage

The page that stops every other page from lying.

It opens with the sentence that matters: a failed scan and a clean scan are
indistinguishable in every aggregate. Findings absent from a repository with a
gap are not absent because they were fixed — nobody looked.

Each gap tells you:

* whether it is **total** (nothing ran) or **partial** (some tools ran), and if
  partial, which signals are still current and which were lost;
* the **cause**, and the **owner** — an infrastructure failure and a repository
  problem go to different people;
* how many runs in a row have produced no data, and how long it has been;
* how many findings are unaccounted for as a result, with a link to them.

A repository that has **never** been scanned says "never scanned" rather than
"0 hours", because an age that does not exist should not be rendered as a
small one.

---

## History

Every run, and trends over time.

Three markers on the chart exist to stop the wrong conclusion:

* a **red dot** — that run did not cover the fleet, so a dip there may be a
  coverage gap rather than a fix;
* a **gold dot** — the scanner image changed at that run, so a step change may
  be the scanner rather than the fleet;
* the **run kind** is stated, because a weekly sweep and a one-repository
  rescan are not comparable.

You can pick two runs and compare them: which findings appeared, which stopped
being observed, and — where the data supports it — which changed state.

---

## Repositories

Per-repository profile, open findings, the dependency inventory, open pull
requests, and the remediation windows in force.

A repository with **no test suite** is flagged prominently. It matters because
without tests there is no way to prove a fix worked, so the system does not
attempt automated fixes there at all.

---

## Waves

When a vulnerability is inside a module your own organisation owns, fixing it
once fixes it everywhere — but only in the right order. A wave shows:

* the upstream fix, and how long it has been waiting;
* **two separate numbers**: how many repositories *depend* on the module, and
  how many actually *reach* the vulnerable code. They are never merged, because
  a two-repository problem presented as twenty is believed once;
* consumers that the wave **cannot** advance, with the reason, shown inside the
  wave rather than dropped from it;
* the steps that clear it, in order — including the publication step when a
  merge alone is not enough.

---

## Reports

Every report the system has issued, each anchored to a completed run, each with
a content hash you can copy. A report can be downloaded again without being
regenerated, so a copy circulated months ago can be checked against the
original.

There is deliberately no "current" report. A report anchored to *now* could not
be reproduced, and a citation to it could not be checked.

---

## If something goes wrong

Every error says what failed and what you can do about it. Two are worth
recognising:

* **"the response was rejected"** — a response contained something shaped like
  a live credential and the interface refused to render it. Nothing was shown.
  This is a defect in whatever produced the value, not in your query.
* **"the response did not match this interface"** — the backend and the
  interface are different versions. Run `./setup.sh` again to regenerate the
  types. The interface refuses to render a response it cannot fully understand
  rather than showing you part of it.
