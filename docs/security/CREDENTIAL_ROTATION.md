# Credential Rotation Runbook

This is the operational runbook for the credentials this repository exposed, and
for the one new secret the remediation requires an operator to create. It is a
sequence of steps to execute at a keyboard, in order, against real infrastructure.

**It covers two different jobs, and they happen at different times.** Provisioning
the configuration the hardened code needs comes **before** the deployment, because
the application refuses to start without it. Revoking and replacing the exposed
credentials comes **after** the deployment has been verified, because that work
cannot be rolled back. [Section 2](#2-the-three-stages) sets out the stages and
[Section 1.1](#11-why-the-order-is-what-it-is) explains why the order is not
interchangeable.

**Use this runbook when** you are deploying this remediation for the first time
(all three stages), or at any later time a credential named in
[Section 3](#3-credentials-in-scope) is suspected of having leaked (Stage C for
that credential alone).

**Who executes it.** An operator with administrative access to the database, the
Google Cloud project, the deployment's secret store, the listing-provider (Zillow)
developer console, the deployment's log store or log-aggregation service, and the
PayPal developer dashboard. Some steps require more than one of these, so read
[Section 3](#3-credentials-in-scope) end to end before starting and confirm you
hold every access it needs.

---

## 1. Read this first

Three facts govern everything below. All three change how you should behave, so
they come before the steps rather than after them.

### 1.1 Why the order is what it is

Two constraints pull in opposite directions, and the stages exist to satisfy both.

**The hardened code will not start without its configuration.** The settings module
validates security-critical configuration at import and fails startup on a value
that is missing, weak, placeholder-shaped or internally inconsistent. Seven
settings have no default at all, and one of them — the PayPal webhook identifier —
does not exist anywhere yet and must be created by an operator in the PayPal
dashboard. **So that provisioning has to happen before the deployment, not after
it.**

**Rotating an exposed credential cannot be rolled back.** Once a credential is
revoked the old value is gone; there is no revert that restores it. So rotation is
scheduled after the deployment has been verified, when a failure can be
distinguished from a failure of the release.

Those two facts are why this runbook is staged rather than linear, and why the
"rotation is sequenced last" instruction applies to Stage C alone. Concretely:

1. Schedule Stage C in **its own change window**, separate from the code
   deployment. Do not fold it into a release.
2. Treat Stage C as an irreversible operation for change-approval purposes. It is
   flagged as such for the deployment reviewer in
   [`../review/CRITICAL_DECISIONS.md`](../review/CRITICAL_DECISIONS.md).
3. Stage A is reversible and is **not** an irreversible operation. Provisioning a
   new secret creates something; it destroys nothing.
4. If a step fails, recover **forward** — see
   [Section 5.4](#54-if-something-goes-wrong).

### 1.2 Every previously exposed credential is already compromised

This runbook covers two different kinds of work, and conflating them leads an operator
to look for an exposure that never happened, or to skip a step that matters:

| | Previously exposed credentials | New credential to provision |
|---|---|---|
| Which | Sections [3.1](#31-database-credentials), [3.2](#32-google-cloud-service-account-key) and [3.3](#33-jwt-signing-key) | Section [3.4](#35-paypal-webhook-identifier-first-time-provisioning-not-rotation) |
| Was the value ever committed? | Yes | **No** |
| Why it is here | Incident response for a value in this repository's history | It is required by the remediation, must be created by an operator, and belongs in the same change window |
| Steps 1 and 3 apply? | Yes | Not on first provisioning &mdash; there is nothing to revoke and nothing in history to remove |

**For the three previously exposed credentials, do not reason about whether the values
leaked. Assume they did, and act accordingly.** The paragraphs below concern those
three.

The webhook identifier is different and is stated as such where it appears: it is new
configuration rather than an exposure, so Section 3.4 is a provisioning procedure that
follows the same four headings for consistency and says explicitly which of them are
inapplicable. If you are re-issuing a webhook identifier that has already been in use,
all four apply again.

**Three credentials were exposed** — the database credentials, the Google Cloud
service-account key and the JWT signing key. For these, do not reason about
whether the value leaked. Assume it did, and act accordingly.

**This runbook covers two categories of credential, and only the first is
compromised.** Keeping them apart matters operationally, because the two require
different work and conflating them makes an operator do the wrong thing for one of
them.

| Category | Which credentials | Status | What the runbook asks for |
|---|---|---|---|
| **Exposed — treat as compromised** | The database connection string and the cloud service-account key that the orchestration definition committed, and the signing key wherever the developer setup script's placeholder was ever used | Present in Git history. Assume disclosed | The full four-step sequence in order: revoke, rotate, delete from history, review prior access |
| **New configuration — never exposed** | The PayPal webhook identifier | Introduced by this remediation. It was never committed and has no history to delete from | Provision it, in the same change window, because the webhook verifier cannot function without it. Its own steps at [Section 3.5](#35-paypal-webhook-identifier-first-time-provisioning-not-rotation) already say so: step 1 is skipped on first provisioning and step 3 records that there is nothing to remove |

For the exposed category, the reasoning is the reason this runbook exists. The
remediation removed those values from the working tree. **That is not the same as
removing them from the repository.** Git history is permanent: the values remain in
every commit that ever carried them, and every clone anyone has ever taken carries
that full history. A value deleted from the current tree is still readable by anyone
holding a clone, a fork, a mirror, a backup or a CI cache.

Removal stops *future* exposure. Only revocation and rotation address the exposure
that has already happened.

For the new-configuration category none of that applies, and saying otherwise would
send an operator looking for history that does not exist. It appears in this runbook
for a different reason: it is a secret that an operator must provision by hand in the
same window, and no code change can produce it.

**One credential is new and was never exposed:** the PayPal webhook identifier. It
is a secret in its own right and it belongs in this runbook because an operator has
to create it and no code change can, but it is **not compromised**, there is
nothing to revoke on first provisioning, and nothing to remove from history. It is
provisioned in Stage A, and only ever rotated later if it is itself suspected of
having leaked.

Do not apply compromise language to the webhook identifier, and do not apply
"provision it" language to the three exposed credentials — those already exist and
must be **replaced**, which is a different action with a different risk.

### 1.3 Three kinds of service impact, defined once

The credentials differ in what changing them does to a running service, and three
distinct effects get conflated if they are not named. This runbook uses these terms
and only these:

| Term | What it means | How long |
|---|---|---|
| **Outage** | The service cannot serve requests successfully until the replacement value is in place, because a dependency it needs is unreachable or unauthorized | From revocation until the replacement is delivered and the process has read it |
| **Process restart** | The process must be restarted to read the new value, but nothing is unreachable in the meantime | One rolling restart |
| **Session invalidation** | Every signed-in user is signed out and must authenticate again. The service itself stays healthy throughout | Immediate, and users recover by signing in |

An outage always implies a restart. Session invalidation implies a restart and does
**not** imply an outage. Every table and every prose statement below classifies a
credential using exactly these three terms, so the classification does not have to
be re-derived from context.

### 1.4 Where this document sits among its siblings

Four documents carry this remediation's written record, and each answers a
different question. This runbook **sequences**;
[`DECISION_LOG.md`](DECISION_LOG.md) **argues**;
[`TRACEABILITY_MATRIX.md`](TRACEABILITY_MATRIX.md) **maps**;
[`RESIDUAL_RISK.md`](RESIDUAL_RISK.md) **evidences**.

This runbook explains *why its own step order is what it is*, because an operator
who reorders the steps defeats the control. It does **not** re-argue the design
decision behind rotating at all, or behind deferring rotation to a separate
window. That reasoning, with the alternatives weighed and the risks accepted, is
recorded once in [`DECISION_LOG.md`](DECISION_LOG.md) — Section 16, row 16.6 — and
is not repeated here.

The authority for this runbook is the Agent Action Plan, sections 0.5.1.5 and
0.12.3.

---

## 2. The three stages

The work divides into three stages. They run in this order, and the boundary between
B and C is a change window rather than a step.

| Stage | What happens | When | Reversible? |
|---|---|---|---|
| **A — Provision** | Create every value the hardened code requires and does not have: the PayPal webhook identifier in the PayPal dashboard, a real signing key, and the remaining required settings, delivered through the secret store | **Before** the new code is deployed | Yes — nothing is destroyed |
| **B — Deploy and verify** | Apply the migrations, deploy the new code, confirm it starts and is healthy, and confirm the security gates pass | After A, in the release window | Yes — by rollback |
| **C — Revoke and rotate** | Revoke and replace the three exposed credentials, remove them from history, and review prior access | **After B is verified**, in its own change window | **No** |

### 2.0 Stage A — provision what the new code requires

Do this first. The application validates configuration at startup and refuses to
run on a missing or weak value, so a deployment that has not been through Stage A
will not come up, and the failure will name a setting rather than the cause.

1. **Create the PayPal webhook identifier.** Follow
   [Section 3.5](#35-paypal-webhook-identifier-first-time-provisioning-not-rotation). Nothing else in this runbook can
   substitute for it: the verifier includes it in the payload it posts to PayPal, so
   without it the webhook route cannot distinguish a genuine notification from a
   forged one.
2. **Generate a real signing key** to the length
   [Section 3.3](#33-jwt-signing-key) specifies, and place it in the secret store
   under the name the application reads. At this stage you are supplying a value the
   new code needs; the *revocation* of the exposed one happens in Stage C, and for a
   signing key those two are the same action, which is why
   [Section 3.3](#33-jwt-signing-key) is cross-referenced from both stages.
3. **Supply every other required setting** in every environment. Treat
   [`../../.env.example`](../../.env.example) as the contract: it names each
   variable, and seven of them have no default and must be supplied. Confirm each
   value is set **before** deploying, not after.
4. **Confirm the payment mode agrees with the environment name.** See
   [Section 4.5](#45-confirm-the-payment-mode-matches-the-environment). Exercise
   this in a non-production deployment first.

Stage A is reversible and interrupts nothing. It adds values; it removes none.

### 2.1 Stage B — deploy and verify

Apply the migrations, deploy, and confirm the deployment is healthy and the gates
pass. This runbook does not own Stage B — [`../../README.md`](../../README.md) does
— and it is named here only because Stage C's entry condition is that Stage B has
been verified: the application starts, the test suite passes, the migrations have
applied and the deployment reports healthy.

Do not begin Stage C until that is true. Rotating a credential underneath a
deployment whose health has not been established makes the two failures
indistinguishable.

### 2.2 Stage C — revoke and rotate the exposed credentials

Every **previously exposed** credential in [Section 3](#3-credentials-in-scope) —
the three named there — is rotated by the same four steps, in this order. The webhook
identifier in Section 3.5 is presented under the same four headings so that nothing is
skipped by accident, but on first provisioning steps 1 and 3 have nothing to act on and
say so:

| Step | Action | What it achieves | Reversible? |
|------|--------|------------------|-------------|
| 1 | **Revoke** | De-authorizes the credential so it cannot be used, whatever copies of it exist | No |
| 2 | **Rotate** | Issues a replacement and returns the service to working order | No |
| 3 | **Delete from history** | Removes the value from all systems and from commit history | **No — irreversible** |
| 4 | **Review prior access** | Establishes the blast radius from access patterns before the exposure | Yes, it is read-only |

### 2.3 The four steps of Stage C

1. **Revoke.** De-authorize the credential immediately, at the system that issued
   it. Do not wait for a replacement to be ready. After this step the exposed
   value is inert everywhere it exists — in every clone, fork, mirror, backup and
   CI cache — because it is the issuer, not the copy, that decides whether a
   credential works.
2. **Rotate.** Issue a replacement, preferably through automation rather than by
   hand, and deliver it to the service through the secret store rather than by
   committing it. Then confirm the service is healthy on the new value.
3. **Delete from history.** Remove the value from every system that holds it and
   from the repository's commit history. Coordinate this with everyone holding a
   clone, because a rewrite changes commit identifiers.
4. **Review prior access.** Examine access and audit logs covering the period
   before, during and after the exposure, and record what the exposed credential
   was actually used for. This is what turns "a credential leaked" into a
   defensible statement about what did or did not happen.

### 2.4 Why this order is not stylistic

**Revocation comes first because a history rewrite does not de-authorize
anything.** If you delete the value from history before revoking it, you have
removed it from the copy you control and left it **live** inside every clone
anyone already has. The credential still works. You have made the exposure harder
to see without making it smaller — and you have destroyed your own ability to
audit which commit carried it.

Reordering these steps does not merely delay the fix. **It defeats it.** Execute
them as numbered.

Three further properties of the order are worth knowing before you start:

1. **Step 3 is the one that cannot be undone.** Steps 1 and 2 are irreversible in
   the sense that the old value will never be valid again, but the system remains
   consistent and you can always issue another replacement. A history rewrite
   changes commit identifiers permanently and invalidates outstanding clones,
   branches and open reviews. Do it last, deliberately, and announce it.
2. **Step 4 depends on log retention, so start it early.** Access logs expire.
   Begin collecting or exporting the relevant logs as soon as you open the change
   window — before step 1 if you can — even though the analysis is completed
   last. A retention window that lapses mid-rotation cannot be recovered.
3. **The steps are per credential, not per runbook.** Complete all four for one
   credential before moving to the next, unless an outage forces you to revoke
   several at once. Section 3 orders the credentials so that the two whose rotation
   causes an **outage**, as [Section 1.3](#13-three-kinds-of-service-impact-defined-once)
   defines it, come first.

---

### 2.5 How to execute step 3: eradicating a value from history

Each credential above says "delete from history". This is the procedure. It is
written once here because the mechanics are identical whichever value you are
removing, and because the step is the one that goes wrong most often — usually by
being declared finished while several copies of the object are still reachable.

**Before you begin, three preconditions.** Revocation (step 1) is complete and
verified, so nothing below is racing a live credential. You hold a change window,
because a rewrite invalidates outstanding clones. And you have a backup of the
repository as it stands — a mirror clone, `git clone --mirror`, kept offline — so
that a rewrite that removes more than intended can be reconstructed.

**A rewrite is a last step, not a substitute for revocation.** If step 1 is not
finished, stop and finish it. Nothing here makes an un-revoked credential safe.

#### Inventory every ref that carries the value

A rewrite is only as complete as the set of refs it walks. Enumerate them all
rather than assuming the default branch is the whole story:

```bash
git rev-list --all --objects | wc -l          # scale of the history
git for-each-ref --format='%(refname)'        # every local ref, all namespaces
git ls-remote --refs origin                   # every ref the remote publishes
git stash list                                # refs/stash carries a full tree
git notes list 2>/dev/null                    # refs/notes/*
```

Record the list. `refs/heads/*` and `refs/tags/*` are the obvious ones;
`refs/stash`, `refs/notes/*` and any remote-tracking `refs/remotes/*` are the ones
routinely missed, and each holds complete trees.

Then confirm the value is where you think it is, and find every commit that carries
it:

```bash
git log --all --oneline -S'<the exposed value>'
git rev-list --all | xargs -n 50 git grep -n -F '<the exposed value>' --
```

The second form searches the content of every commit rather than only the diffs,
which matters for a value introduced and reintroduced across several commits.

#### Rewrite

Use `git filter-repo`. It rewrites every ref by default, refuses to run on a
non-fresh clone, and does not leave the backup refs that `git filter-branch` leaves
behind:

```bash
git clone --no-local /path/to/repo repo-rewrite && cd repo-rewrite

printf '%s==>REMOVED-ROTATED-CREDENTIAL\n' '<the exposed value>' > /tmp/replacements
git filter-repo --replace-text /tmp/replacements
```

Use `--replace-text` rather than `--invert-paths` when the value is embedded in a
file the repository still needs — which is the case for every credential in this
runbook, since all of them lived in files that survive. `--invert-paths` is for a
file that should never have existed at all, such as a committed key.

Write the replacement list to a path **outside** the repository, as above.
A replacements file committed into the tree is a list of exactly which secrets
existed, which is its own disclosure.

If `git filter-repo` is unavailable, the BFG Repo-Cleaner is an acceptable
substitute for a fixed string. `git filter-branch` is not: it is deprecated,
leaves every original commit reachable under `refs/original/*`, and misses refs
outside the ones it is told about.

#### Expire everything that still reaches the old objects

The rewrite creates new commits; it does not by itself remove the old ones. They
stay reachable through the reflog and stay present in the pack files until both are
cleared:

```bash
git for-each-ref --format='delete %(refname)' refs/original | git update-ref --stdin
git reflog expire --expire=now --expire-unreachable=now --all
git gc --prune=now
```

Then verify locally, before pushing anything:

```bash
git rev-list --all | xargs -n 50 git grep -n -F '<the exposed value>' -- ; echo "exit=$?"
git cat-file --batch-all-objects --batch-check | wc -l
```

The `git grep` sweep must find nothing. `--batch-all-objects` walks every object in
the object database including unreachable ones, so a count that has not fallen
after `gc` means objects survived and the sweep above was searching a smaller set
than the repository actually holds.

#### Publish the rewrite

```bash
git push --force --prune origin 'refs/heads/*:refs/heads/*'
git push --force --prune origin 'refs/tags/*:refs/tags/*'
```

`--prune` is what deletes refs the rewrite removed; without it a branch you dropped
stays on the remote, still carrying the value. Push tags explicitly: a tag pointing
at a pre-rewrite commit keeps that commit — and the value in it — reachable
forever, which is the single most common way a completed-looking rewrite fails.

#### Deal with the copies a push cannot reach

A force-push updates the refs you control. It does not touch any of the following,
and each holds the value until it is dealt with individually:

1. **Hidden refs on the hosting provider.** Pull-request and merge refs
   (`refs/pull/*` and equivalents) are created by the host, are not writable by a
   client, and keep their commits reachable after the branch is gone. They are not
   removed by a force-push or by any client-side command. Ask the provider's
   support to garbage-collect the repository, and reference this rotation when you
   do. Until they confirm, treat the value as still published.
2. **Forks.** A fork is a separate repository with its own object store and its own
   refs. Rewriting the upstream changes nothing in it. Enumerate the forks, and for
   each one either have its owner repeat this procedure or delete the fork. A fork
   you cannot reach the owner of is an exposure you must record as unresolved.
3. **Mirrors, backups and archives.** Any `--mirror` clone, backup snapshot, or
   repository archive taken before the rewrite still contains the value. Rotate or
   destroy them under the same change window, and note that the offline backup this
   procedure told you to take is itself one of them — destroy it once the rewrite is
   verified.
4. **CI caches, build artefacts and published releases.** A cached checkout, a
   stored build artefact, a release asset, or a container image built from the old
   tree can each carry the file verbatim. Purge the caches, delete artefacts built
   before the rotation, and rebuild and republish any image that embedded the value.
5. **Everything derived from a checkout.** Deployment manifests, configuration
   management state, ticket attachments and chat history are covered per credential
   in Section 3; they are listed again here because they are part of the same step
   and are not reached by any git command.

#### Re-clone is mandatory, not advisory

Every person and every automated system holding a clone must **delete it and clone
afresh.** This is not tidiness. A `git pull` or `git merge` into a pre-rewrite clone
reintroduces the old commits — and the credential with them — and the next push
republishes them. One stale clone undoes the entire rewrite.

Announce the rewrite with the specific instruction:

```bash
cd .. && rm -rf <clone-directory> && git clone <remote-url>
```

Anyone with local work should export it as patches **before** deleting the clone
(`git format-patch`), confirm no patch carries the exposed value, and reapply the
patches to the fresh clone. Open reviews must be closed and reopened against the
rewritten history; a review branch is a ref, and a ref keeps commits alive.

---

---

## 3. Credentials in scope

Seven credentials require operator action. **These are called out separately from
the remediation's code changes precisely because none of them can be remediated by
a code change alone.** They fall into two groups that need different treatment, and
the tables are split so the difference cannot be read past.

**Group 1 — exposed, and therefore compromised. Handled in Stage C.** The code
changes stop these values being committed again; only revocation and replacement
address the values that were already committed. Impact is classified with the terms
[Section 1.3](#13-three-kinds-of-service-impact-defined-once) defines.

| # | Credential | Where it was exposed | Impact of replacing it |
|---|------------|----------------------|------------------------|
| 1 | Database credentials | `infrastructure/docker/docker-compose.yml:30` | **Outage**, plus a process restart — the application cannot reach the database between revocation and the replacement being read |
| 2 | Google Cloud service-account key | `infrastructure/docker/docker-compose.yml:46-47` and `:49` | **Outage**, plus a process restart, on any host running the Cloud SQL proxy from a key file. No impact where the proxy already uses ambient credentials |
| 3 | JWT signing key | `scripts/setup_dev_environment.sh:54` | **Session invalidation**, plus a process restart. **No outage** — the service stays healthy and every signed-in user simply re-authenticates |
| 4 | Listing-provider (Zillow) API key | Never committed, but written to standard output by `backend/app/services/zillow_service.py:27` and carried in query strings at `:15-19` | **Process restart** only. Listing ingestion pauses between revocation and the replacement being read; the service keeps serving the listings it already holds |

**Group 2 — new, never exposed, not compromised. Provisioned in Stage A.**

| # | Secret | Status | Impact of provisioning it | Kind of work |
|---|--------|--------|---------------------------|--------------|
| 5 | PayPal webhook identifier | **Never exposed** — new configuration, created by an operator for this remediation and never committed | **Process restart** only. Until it is provisioned the webhook route refuses inbound notifications, which is a feature being unavailable rather than an outage of the service | **First-time provisioning** |
| 6 | Seeded administrator credential | **Never exposed** — new configuration, created by an operator for this remediation and never committed | **No outage and no restart.** Until it is provisioned the administrator account cannot be signed in to, which is an account being unusable rather than an outage of the service | **First-time provisioning** |
| 7 | Shared rate-limit store address | **Never exposed** — new configuration, provisioned by the infrastructure and never committed | **Outage** outside a local run: the application refuses an in-process store and does not start without this value | **First-time provisioning** |

Line references identify the **original** committed state of each file — the state
that persists in history. The current working tree no longer carries these values. Row 4
has no such reference because there is no committed value to point at.

**Which credentials cause an outage.** Exactly two: the database credentials and
the service-account key, and only because both mediate access to the database.
Section 3 orders them first for that reason. The signing key does not cause an
outage; it invalidates sessions. That distinction is used consistently here and in
[Section 5.1](#51-stage-c-gets-its-own-change-window).

### 3.1 Database credentials

**What it is.** A database connection string carrying an embedded username and
password, committed as a literal at
`infrastructure/docker/docker-compose.yml:30`. The same file supplied it to the
application on every container start, so it was the working credential for the
deployed service and not merely an example.

The remediation replaced that literal with a required reference to an externally
supplied environment variable. **That change only stops future exposure.** The
committed value remains in history and must be rotated.

A second copy of the same pattern exists at `scripts/setup_dev_environment.sh:55`,
which wrote a credentialed connection string into every developer's environment
file, and `scripts/setup_dev_environment.sh:69` created a local database user with
a hardcoded password. Treat any database user created by that script as exposed
too.

1. **Revoke.** Remove the exposed database user's privileges and disable its
   ability to authenticate. If the user owns objects, do not drop it — reassign
   ownership first, then revoke, so that revocation does not cascade into data
   loss. Confirm the old credential is rejected by attempting one authentication
   with it and observing that it fails.
2. **Rotate.** Create a replacement database user with the least privilege the
   application needs, or set a new password on the retained user. Write the new
   connection string into the secret store, never into a file in the repository.
   Restart the application so it reads the new value, then confirm the health and
   readiness endpoints report healthy and that the migration state is unchanged.
3. **Delete from history.** Remove the value from the repository's history and from
   every other system that holds a copy — deployment manifests, configuration
   management, CI variables, ticket attachments, chat logs and local environment
   files on developer machines. Every developer who ever ran the setup script has
   an environment file containing the same pattern; instruct them to delete it and
   regenerate it from the template.
4. **Review prior access.** Pull the database's authentication and connection logs
   for the retention window and identify every source address and application that
   authenticated as the exposed user. Anything you cannot attribute to a known
   deployment is an incident, not a curiosity. Record the finding either way.

### 3.2 Google Cloud service-account key

**What it is.** A Google Cloud service-account key that the Cloud SQL proxy
consumed from a host directory bind-mounted into the container at
`infrastructure/docker/docker-compose.yml:46-47`, and which was named as the
credential path at `infrastructure/docker/docker-compose.yml:49`.

**The exposure is structural rather than accidental.** The file's own trailing
comment at `infrastructure/docker/docker-compose.yml:65-67` instructed the reader
to place the credentials file in the `./secrets` directory, so the arrangement only
ever worked if real key material was present inside the repository tree — and no
`.gitignore` existed at any level of this repository to stop that key being
committed. The instruction distributed a long-lived key to every machine that ran
the stack.

**One precision that changes step 3 for this credential.** A search of every commit
on every ref in this repository finds no key material ever added: the committed
artefacts are the mount, the credential path and the instruction, not the key
itself. So the history rewrite is **conditional** — search first, rewrite only if a
search finds something. That does not soften steps 1, 2 and 4. The key must still
be treated as compromised, because the repository told every operator to put one
there and nothing prevented them from committing it.

1. **Revoke.** In the Google Cloud console or by command line, disable and then
   delete the service-account key. Revoke the key, not the service account, unless
   the account itself is unused. If you cannot identify which key was distributed,
   revoke every key on that service account — an unidentified key is an active
   exposure.
2. **Rotate.** Prefer **not** issuing a replacement key at all. The proxy supports
   ambient credentials, so on a managed platform the workload identity supplies
   credentials with no key material at rest, which removes this credential class
   permanently rather than replacing it. Issue a replacement key only where a
   host genuinely cannot use ambient credentials, and store it in the secret store
   rather than in a repository directory. Then confirm the proxy authenticates and
   the application reaches the database.
3. **Delete from history.** Search every clone, fork and mirror for key material
   under the `secrets/` path and for credential JSON files, and remove anything
   found from history. Search developer machines as well as the repository: the
   instruction at `:65-67` was addressed to them, so an un-ignored key file is
   more likely to sit in a working tree than in a commit.
4. **Review prior access.** Review the service account's activity in the cloud
   audit logs for the retention window. Identify every principal and source that
   used the key, and confirm each corresponds to a known deployment. Record what
   the service account was entitled to do, because that — not the key itself —
   defines the blast radius.

### 3.3 JWT signing key

**What it is.** The key the service uses to sign and verify access tokens. Rotate
it in every environment where the placeholder written by
`scripts/setup_dev_environment.sh:54` was ever used. That line wrote the literal
`your_secret_key_here` into the environment file the script generated.

**Why that placeholder was a live signing key, not an inert stub.** The settings
module performed no validation whatsoever — it declared eight settings and not one
validator — so nothing rejected the placeholder. It was accepted and used to sign
tokens exactly as a real key would be. The consequence is blunt: **anyone who has
read this project's setup script knows the signing key of every deployment that
never changed it,** and can mint a token for any account.

If you are unsure whether an environment ever used the placeholder, assume it did.
The script wrote it unconditionally.

1. **Revoke.** For a signing key, revocation and replacement are the same action:
   the key is de-authorized by ceasing to accept signatures made with it. There is
   no issuer to call. Proceed directly to step 2 and treat the moment the new key
   is in force as the moment of revocation. Do not configure the service to accept
   the old key alongside the new one during a transition — that would leave the
   publicly known key valid, which is the exposure you are closing.
2. **Rotate.** Generate a cryptographically random replacement, with a tool, never
   by typing one.

   **The required length is not a single number — it is set by the strongest
   algorithm named in `JWT_ALGORITHMS`,** because RFC 7518 section 3.2 requires an
   HMAC key to be at least as long as the hash output. A configuration naming
   several algorithms takes the largest floor of those named:

   | Strongest algorithm in `JWT_ALGORITHMS` | Minimum key length, in UTF-8 bytes |
   |---|---|
   | `HS256` | 32 |
   | `HS384` | 48 |
   | `HS512` | 64 |

   Read the deployment's own `JWT_ALGORITHMS` value before generating, and size the
   key to the strongest entry it names. The startup validator enforces exactly this
   floor and reports the byte count it wanted, so a key that is long enough for
   `HS256` but not for a configuration that also names `HS512` fails startup rather
   than being accepted.

   Either command below produces **64 bytes**, which clears the floor for all three
   algorithms and is therefore the safe default regardless of the configured
   allowlist. A signing key that reaches a terminal is retained by scrollback, shell
   history, the CI job log, a screen share and any support transcript of the session,
   so printing it converts one exposure into several. Disable command tracing first,
   then stream the value straight into the managed secret version without it ever
   being displayed:

   ```bash
   set +x
   python -c "import secrets, sys; sys.stdout.write(secrets.token_urlsafe(48))" |
     gcloud secrets versions add SECRET_KEY --data-file=- --project "${PROJECT_ID}"
   # or, equivalently
   openssl rand -base64 48 |
     gcloud secrets versions add SECRET_KEY --data-file=- --project "${PROJECT_ID}"
   ```

   If the destination is a file rather than a managed secret, create it under a
   restrictive umask and never `cat` it:

   ```bash
   set +x
   ( umask 077; python -c "import secrets, sys; sys.stdout.write(secrets.token_urlsafe(48))" \
       > "${SECRET_KEY_FILE:?name the destination}" )
   ```

   **Verify by identifier, not by value.** Confirm the new version exists and is
   enabled without reading it back:

   ```bash
   gcloud secrets versions list SECRET_KEY --project "${PROJECT_ID}" --limit 3
   ```

   The validator also enforces variety rules — at least 12 distinct characters, no
   character repeated more than three times in a row, no run of more than four
   consecutive code points, and no placeholder or well-known value. A generated
   value effectively always satisfies these; if one is refused, generate another.
   [`../../.env.example`](../../.env.example) is the authority for the full rule set.

   The command above has already written the new version under the variable name
   the application reads. Restart the service. **Expect session invalidation, not an outage:** tokens
   signed with the old key no longer verify, so every signed-in user is signed out
   and re-authenticates, while the service itself stays healthy. Plan the change
   window accordingly and tell support in advance. Confirm afterwards that a fresh
   sign-in succeeds and returns a token, and that the response shape is unchanged.
3. **Delete from history.** The placeholder literal itself is not a secret and does
   not need scrubbing — it is a publicly known string, and it is on the startup
   denylist precisely so it can be named. What must be removed is any **real**
   signing key that was ever committed or pasted into a tracked file, a CI
   variable, a ticket or a chat message. Search for those and remove them. Also
   delete the generated environment files on developer machines, since every one of
   them carries the placeholder and will now be refused at startup anyway.
4. **Review prior access.** Token signing leaves no issuer-side log, so review the
   application's own authentication and authorization records instead: look for
   access that succeeded without a corresponding sign-in, for tokens presenting
   claims the service would not have minted, and for privileged actions attributed
   to accounts that were not in use. Record the window during which the placeholder
   was in force, because that window bounds what a forged token could have done.

**One control now makes this failure visible rather than silent.** The hardened
settings module refuses to start when the signing key is the literal
`your_secret_key_here`, or is shorter than the floor its configured algorithm sets.
A deployment that still carries the placeholder will now fail loudly at startup
instead of quietly issuing forgeable tokens. Measured against the current code: that
literal is rejected, an undersized key is rejected with the byte count it required,
and a key generated by either command above is accepted.

**A note on stages.** For a signing key, revocation and replacement are one action,
so this section is reached from both stages. **Stage A** uses it to generate the key
the new code needs in order to start at all. **Stage C** uses it, together with
steps 3 and 4, to close out the exposure of the placeholder: removing any real key
that was ever committed, and reviewing what a forged token could have done during
the window the placeholder was in force. If Stage A generated a fresh key, Stage C's
step 2 is already satisfied for this credential and only steps 3 and 4 remain.

### 3.4 Listing-provider (Zillow) API key

**What it is.** The API key the ingestion task authenticates to the listing
provider with. It was never committed as a literal — it arrived from
configuration — but it was exposed at runtime by two defects that compounded each
other:

1. `backend/app/services/zillow_service.py:15-19` placed the key in the request's
   **query parameters**, so the full key travelled inside the request URL. A URL is
   recorded in far more places than a header: the provider's access logs, any
   forward or reverse proxy on the path, and any client-side or intermediary
   request log.
2. `backend/app/services/zillow_service.py:27` printed the exception text on
   failure with a bare `print()`. The HTTP library embeds the **full request URL**
   in its exception messages, so a single upstream failure wrote the key to
   standard output — and from there to the container log, and from there to
   whatever log store or aggregation service collects it. There was no logging
   framework, so there was no interception point at which the value could have been
   redacted.

The remediation moved the key into a request header, added a request timeout, and
replaced the `print()` with the redacting structured logger. **That stops future
exposure. It does nothing about the log records already written**, which is why
this key belongs in this runbook.

**Treat it as exposed.** Do not reason about whether an upstream failure ever
occurred. Any deployment that ran the previous code with a real key must be treated
as having disclosed it, and any log store that retained those records must be
treated as holding it in plaintext.

1. **Revoke.** Revoke or regenerate the key in the listing provider's developer
   console — the issuing system, not this repository. Where the provider supports
   multiple keys, delete the exposed key outright rather than only issuing a second
   one; an unrevoked key remains usable regardless of what else exists. Confirm the
   old key is rejected by making one request with it and observing a rejection.
2. **Rotate.** Issue a replacement key in the provider's console. Write it into the
   secret store under the variable name the application reads, never into a file in
   the repository. Restart the service, then confirm ingestion completes a cycle
   against the provider and that the request carries the key in a **header** — the
   current code sends it in a header and in no query parameter, and the service
   tests assert that. Where the provider offers key restrictions — an address
   allowlist, a referrer restriction, a per-key scope or a rate cap — apply them to
   the replacement so that a future disclosure is worth less than this one.
3. **Delete from the stores that hold it.** The exposure is in logs rather than in
   the repository, so this step is a search of the log estate:
   - the deployment's container or pod logs, and any retained rotated files;
   - the log-aggregation or observability service the deployment ships to, including
     its search indexes and any saved query results or dashboards;
   - any proxy, load-balancer or gateway access logs that record full request URLs;
   - build and continuous-integration job logs, and any artifact retaining them;
   - developer machines: shell scrollback, saved terminal transcripts, and local
     `.env` files.
   Purge or rotate every store that holds a matching record. Where a store cannot be
   purged, record that it cannot and shorten its retention. **Also search the
   repository's history**, because the value could have been pasted into an issue,
   a fixture or a committed log excerpt at some point; the search is cheap and its
   absence is worth recording either way.
4. **Review prior access.** Pull the provider's own usage or access logs for the key
   over the retention window and reconcile the request volume, the source addresses
   and the endpoints called against what this deployment's ingestion task should
   have produced. Ingestion runs on a schedule with a predictable shape, so an
   unexplained burst, an unfamiliar source address or a call to an endpoint this
   service does not use is an incident rather than a curiosity. Record the finding
   either way, and note any quota or billing anomaly separately — a stolen key is
   often first visible as unexpected usage.

### 3.5 PayPal webhook identifier (first-time provisioning, not rotation)

> **This is a Stage A step, not a Stage C one.** This secret is **new and was never
> exposed**, so it is not compromised, there is nothing to revoke and nothing to
> remove from history. It appears in this runbook because an operator must create it
> and no code change can. It must exist **before** the new code is deployed, because
> `PAYPAL_WEBHOOK_ID` has no default and the settings module refuses to start
> without it.

This is the one section of this runbook that is **not** incident response. Nothing
here leaked; the work is creating a credential the remediation needs and that only an
operator can create. It follows the same headings as the rotations above so that a
reader working down the runbook does not skip it, and each heading states plainly
where it does not apply.

**What it is.** The identifier of the webhook subscription registered in the PayPal
dashboard. It is a secret in its own right and is required by the remediation.

**Why it has to exist before the deployment.** Two reasons, and either is
sufficient. First, `PAYPAL_WEBHOOK_ID` is one of the seven settings with no
default: startup fails outright if it is absent, so a deployment without it does not
run. Second, the webhook verifier includes this identifier in the payload it posts to
PayPal to confirm a notification's signature — without it there is nothing to verify
against, so the route could not distinguish a genuine PayPal notification from a
forged one.

#### Stage A — provisioning it for the first time

1. **Create the webhook subscription** in the PayPal dashboard, pointing it at the
   deployment's webhook route and subscribing to the payment events the service
   handles.
2. **Copy the identifier PayPal issues into the secret store** under the variable
   name the application reads. Never into a file in the repository.
3. **Confirm the certificate-host allowlist** setting names only PayPal-owned
   hosts, because the verifier validates the inbound certificate host against it
   before the certificate URL is used.
4. **Then deploy.** The service will start; before this value was present it would
   not have.

That is the whole of Stage A for this secret. Do not perform revocation or history
removal — neither has a subject here.

#### Later — rotating it, only if it is itself suspected of having leaked

This path is Stage C's four steps, and it applies only to an identifier that has
already been in use and is now suspect. It is not part of deploying this
remediation.

1. **Revoke.** Delete the old webhook subscription in the PayPal dashboard, so
   notifications signed against it stop being accepted.
2. **Rotate.** Re-create the subscription as in Stage A above and place the new
   identifier in the secret store. Restart the service.
3. **Delete from history.** Only if the identifier was committed somewhere: remove
   it as in Section 3.1 step 3. For an identifier that only ever lived in the secret
   store there is nothing to remove — confirm that, rather than assuming it.
4. **Review prior access.** Review the webhook delivery history in the PayPal
   dashboard alongside the service's own webhook logs, and confirm the two agree on
   which notifications were delivered and accepted.

**One historical review worth doing once, at either stage.** Before this remediation
the service performed no signature verification at all, so treat any subscription
state change that predates it as unverified in origin and reconcile it against
PayPal's record of settled payments rather than against the service's own rows. That
is a review of past data rather than of this credential, and it does not make the new
identifier compromised.

**A note on scope while you are in the payment configuration.** This remediation
retains the PayPal hosted redirect, so no card number enters or is stored by this
service. Every value handled here is an order identifier, a plan identifier, a
client credential or a webhook identifier. Do not change the payment flow to
collect card details in the service while working through this runbook.

### 3.6 Seeded administrator credential

**What it is.** The password of the single administrative account,
`test@blitzy.com`. **It was not previously exposed — this is new configuration.**
Revision `0002` grants that address the administrative role and stores
`!locked-no-password-set`, which is not a hash any password produces. The account
therefore holds the role and cannot be signed in to until an operator provisions a
credential. No credential is embedded in a migration, in a manifest or anywhere in
this repository, which is why this step exists at all.

**Provision it after the schema migration and before anyone needs administrative
access.** The account does not exist until revision `0002` has applied, so ordering
matters. Until the step below runs, the deny-by-default authorization model simply
has no reachable administrator — which is a safe state, not a broken one, and is why
this is not part of an automatic release.

The step is `backend/app/core/admin_provisioning.py`. It reads the credential only
from `ADMIN_SEED_PASSWORD` and never from an argument, so the value does not reach a
shell history or a process listing. It writes only to the fixed address above,
refuses an account that does not already hold the administrative role — so it cannot
grant privilege — holds the credential to the same policy every account is held to,
and re-asserts that exactly one account holds the role before committing. It records
the outcome and the administrator count through the redacting logger; no record
carries the credential.

1. **Revoke.** Nothing to revoke on first provisioning; skip this step. When
   rotating a credential already in use, note that this service issues stateless
   tokens with no revocation mechanism, so a token already issued to the
   administrator stays valid until it expires. Treat the token lifetime as the
   window during which the previous credential still confers access, and rotate the
   JWT signing key as in Section 3.3 if that window is unacceptable.
2. **Rotate.** Store the new credential in the secret store under
   `ADMIN_SEED_PASSWORD`. It must satisfy the account policy the service enforces:
   at least 12 characters, at most 72 UTF-8 bytes, and an uppercase letter, a
   lowercase letter, a digit and a special character. Then run the step:

   ```bash
   # Locally, from the repository root.
   ADMIN_SEED_PASSWORD='<the new credential>' \
     python -m backend.app.core.admin_provisioning
   ```

   In a deployed environment, apply the operator Job instead, which receives the
   credential from Secret Manager under its own least-privilege identity so the
   serving workload never mounts it:

   ```bash
   # After the migration Job has completed.
   PROVISION_ADMIN_CREDENTIAL=true scripts/deploy.sh
   ```

   **Provisioning a locked account needs nothing further.** Replacing a credential
   already in place is refused unless you ask for it explicitly, so a rotation also
   sets `ADMIN_CREDENTIAL_RESET=true`. That refusal is deliberate: it means a
   repeated deployment cannot silently overwrite a working administrator
   credential.

3. **Delete from history.** Nothing to remove for a newly issued credential.
   Confirm only that you did not commit it: it belongs in the secret store, and the
   repository's ignore rules already exclude environment files. `.env.example`
   carries a placeholder rather than a value.
4. **Review prior access.** Confirm the run reported the outcome you expected —
   `provisioned` on first use, `reset` on a deliberate rotation, `unchanged` if a
   credential was already in place — and that the record states an administrator
   count of one. Then review the sign-in history for the administrative address. If
   the account was ever reachable with a credential you did not set, treat it as
   compromised, rotate again, and rotate the JWT signing key with it.

**Unset the reset flag afterwards.** Leave `ADMIN_CREDENTIAL_RESET` at `false`
outside a rotation window. While it is `true`, every run of the step replaces the
administrator's credential with whatever the secret store currently holds.

### 3.7 Shared rate-limit store address

**What it is.** The connection address of the store the rate limiter shares its
counters through, carrying the store instance's own authentication string. **It was
not previously exposed — this is new configuration**, and it is a secret in its own
right because the authentication string is part of the address. Like the webhook
identifier, it is in this runbook because an operator must provision it in the same
change window and no code change can produce it.

**Provision it before a non-local deployment starts.** Outside `ENVIRONMENT=local`
the application refuses an in-process store and requires a shared store's address,
so a deployment without this value does not start. The managed store is provisioned
by the infrastructure configuration; the address is assembled from that instance's
published host and port plus its authentication string, and supplied as the
ephemeral input the secret version reads. The deployment workflow then copies the
secret's current version into the cluster, refusing any value that names an
in-process scheme.

1. **Revoke.** Nothing to revoke on first provisioning; skip this step. If you are
   rotating an address whose authentication string has already been in use, rotate
   the string on the store instance itself first, so the previous address stops
   being accepted.
2. **Rotate.** Read the store's host and port from the infrastructure output, obtain
   the instance's current authentication string from the store's own management
   interface, assemble the address, and supply it as the ephemeral input. Apply, so
   that a new secret version is created. Re-run the deployment step that copies the
   secret into the cluster, and restart the pods that read it. Counters are not
   persisted, so the traffic that follows rebuilds them and no state is lost.
3. **Delete from history.** Nothing to remove for a newly issued address. Confirm
   only that you did not commit it: no output publishes the authentication string,
   and the infrastructure input that carries the address is declared write-only and
   ephemeral, so applying it does not persist the value in state.
4. **Review prior access.** Review the store instance's own access logs, and confirm
   that only the workloads intended to share counters have connected. An address
   that reached a wider audience should be treated as compromised and rotated,
   because a caller holding it can read and reset every rate-limit counter.

**One property to preserve while you are here.** The address must name a store every
process shares. An in-process scheme in this value would silently return the service
to counting per process, which is the weakness `docs/security/DECISION_LOG.md` row
2.5 refuses and row 35.36 records as the controlling decision. The deployment step
refuses those schemes, and so does startup validation.

---

## 4. Verification

These checks are manual because no automated gate can confirm them — each asks
whether an operator did something, or whether a value placed outside the repository
is the right value.

**Two of them belong to Stage A and are performed before the deployment**, because
they establish that the configuration the new code needs is correct:
[4.4 Confirm the replacements are delivered through the secret
store](#44-confirm-the-replacements-are-delivered-through-the-secret-store) — read as
"the values" at Stage A — and
[4.5 Confirm the payment mode matches the
environment](#45-confirm-the-payment-mode-matches-the-environment). The remaining
four belong to Stage C and are performed after rotation. Each section says which.

Record the outcome of every check. An unrecorded verification is indistinguishable
from a skipped one.

### 4.1 Confirm the documented order was followed

For each of the three **previously exposed** credentials, confirm the four steps ran in
order, and **specifically that revocation preceded any history rewrite.** For the
webhook identifier, there is no order to confirm on first provisioning: verify instead
that it exists in the secret store and that it was never committed, which
[Section 4.4](#44-confirm-the-replacements-are-delivered-through-the-secret-store)
covers. Check the timestamps rather than asking:
compare the revocation time recorded at the issuing system against the commit time
of any rewrite. If a rewrite happened first, the credential was live in every
outstanding clone for the interval between the two, and that interval is an
exposure window you must record and assess in the step 4 review.

### 4.2 Confirm no secret value remains in the current tree

**Stage C.** Search the working tree for each rotated value and for the patterns
that carried them. Confirm zero results. Search the full history separately — the working tree
being clean says nothing about history, which is the point of step 3.

For the listing-provider key, extend the same search to the log estate enumerated
in [Section 3.4](#34-listing-provider-zillow-api-key) step 3, because that
credential's exposure is in logs rather than in the repository. A clean repository
says nothing about a log index.

Confirm too that no replacement value was introduced anywhere in the tree while
rotating. It is a common and quiet mistake to remove an old credential and commit
the new one beside it.

### 4.3 Confirm the ignore rules cover every path where a secret previously lived

**Stage C.** **No `.gitignore` existed at any level of this repository before this
remediation** — the mechanism was entirely absent, not merely incomplete, which is
why reintroduction was previously unpreventable. Confirm the root `.gitignore` now
covers each path a secret occupied or was directed to:

1. The **`secrets/` directory** — the path the bind-mount at
   `infrastructure/docker/docker-compose.yml:46-47` used and the comment at
   `:65-67` directed a key into. It is ignored at the root and at any depth.
2. The **`google-credentials.json`** credential file named at
   `infrastructure/docker/docker-compose.yml:49`, along with the broader
   credential-JSON and private-key patterns beside it.
3. The **environment-file family**, with `!.env.example` negated back in so the one
   committed environment template survives while every real environment file stays
   ignored.

Verify the rules actually match rather than reading them, by asking git whether it
would ignore each path. Also confirm `.dockerignore` excludes the same paths, since
the backend image copies the build context and would otherwise bake a local
environment file or secrets directory into a published image.

### 4.4 Confirm the replacements are delivered through the secret store

**Stage A for a newly provisioned value; Stage C for a replacement.** Confirm each
value is supplied from the secret store and is **not** present in any committed file.

Then confirm something subtler: **that the variable the application actually reads
is the variable being supplied.** Check the name, not just the presence of a value.

This is not a hypothetical concern — it is the exact failure this repository had.
`infrastructure/docker/docker-compose.yml:31` supplied the signing key under a
different variable name than the application reads: the compose file set
`JWT_SECRET` while the settings module declared `SECRET_KEY`. Nothing read
`JWT_SECRET`, so the value never arrived at all, and the application fell through to
whatever the environment file held — which, for any environment built by the setup
script, was the `your_secret_key_here` placeholder. A correctly rotated key
delivered under the wrong name is a rotation that did not happen.

Treat [`../../.env.example`](../../.env.example) as the authoritative contract for
variable names. Check every name against it rather than against prose in any other
document, and confirm the deployed environment supplies each required name.

### 4.5 Confirm the payment mode matches the environment

**Stage A.** Confirm the deployed payment mode agrees with the deployment's
environment name,
and that the payment API base agrees with the mode. A production environment
configured against sandbox payment settings is refused at startup by design.

**Exercise this guard in a non-production deployment first.** Confirm there that a
mismatched pair fails to start and that a matching pair starts cleanly, then apply
the configuration to production. Discovering the guard for the first time during a
production start is avoidable.

### 4.6 Post-rotation smoke checks

**Stage C.** Finally, confirm the deployment is genuinely serving on the rotated
credentials rather than on a cached connection or a stale process:

1. **Health.** The health and readiness endpoints report healthy. Readiness answers
   unhealthy while the database is unreachable, so a healthy readiness response is
   positive evidence that the new database credential works.
2. **Authentication.** A fresh sign-in succeeds and returns a token, and the
   response shape is unchanged. A token issued before the signing-key rotation is
   no longer accepted.
3. **Authorization.** A request that should be refused is still refused. Rotation
   changes credentials, not permissions; if a role boundary moved, something else
   changed too.
4. **Webhook.** A notification with an invalid signature is rejected and produces no
   state change, and a genuine delivery from the PayPal dashboard is accepted
   exactly once.
5. **Ingestion.** The listing ingestion task completes a cycle against the provider
   on the replacement key, and the corpus gains or refreshes rows.

### 4.7 Confirm the listing-provider key has left URLs and logs

This check is specific to credential 4, because its exposure route was the
application's own behaviour rather than a committed file. Confirm all four:

1. **The key travels in a header.** Capture or inspect one outbound ingestion
   request and confirm the key appears in a request header and in no query
   parameter, no path segment and no request body.
2. **No log record carries it.** Trigger an ingestion failure deliberately in a
   non-production deployment — point the provider address at an unreachable host —
   and confirm the resulting log record names the failure without reproducing the
   key or the full URL. The redacting logger is what produces that, and the service
   tests assert it, but confirm it in the deployed configuration too, because a log
   pipeline can be configured to capture standard output separately.
3. **No `print()` remains on any path that can touch a secret.** Confirm the
   application emits through the structured logger only. This is what gives
   redaction an interception point at all.
4. **Retention is bounded.** Confirm the log store's retention for the period that
   held the old key has been purged or has expired, and record the date on which the
   last record containing it leaves the estate. If that date is in the future, the
   rotation is complete but the exposure is not yet closed, and that distinction
   belongs in the record.

### 4.8 Confirm the history rewrite left no copy of the value

This check exists because a rewrite is routinely declared finished while several
copies of the object remain reachable. Run it in a **fresh clone** taken after the
force-push, not in the working copy you rewrote — the working copy is the one place
guaranteed to look clean, because it is where you did the work.

```bash
git clone --mirror <remote-url> verify-rewrite && cd verify-rewrite

# 1. No commit, on any ref, carries the value.
git rev-list --all | xargs -n 50 git grep -n -F '<the exposed value>' -- ; echo "exit=$?"

# 2. No object at all carries it, reachable or not.
git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype)' \
  | awk '$2 == "blob" { print $1 }' \
  | git cat-file --batch \
  | grep -c -F '<the exposed value>'

# 3. The refs are the ones you intended, with nothing left over.
git for-each-ref --format='%(refname)'
```

Check 1 must report no match; check 2 must report `0`; check 3 must show no branch
or tag the rewrite was supposed to remove. A non-zero count in check 2 with no match
in check 1 means the value survives in an object no ref reaches — usually a tag you
did not push, or a provider-side pull-request ref — and the value is still
retrievable by anyone who can name the object.

Then confirm the four categories a push cannot reach, from
[Section 2.5](#25-how-to-execute-step-3-eradicating-a-value-from-history), each with
evidence rather than assumption:

| What | Evidence to record |
| --- | --- |
| Provider-side garbage collection | The support request reference and the provider's written confirmation that it completed |
| Forks | The enumerated list, and for each one either the owner's confirmation or the deletion. Any fork you could not reach is recorded as an unresolved exposure |
| Mirrors, backups, archives | Each one rotated or destroyed, including the offline backup Section 3.5 told you to take |
| CI caches, artefacts, images | Caches purged, pre-rotation artefacts deleted, and every image that embedded the value rebuilt and republished |

Finally, confirm the re-clone instruction was carried out. Ask for confirmation per
holder rather than announcing once: a single pre-rewrite clone that is pulled into
and pushed from republishes the old commits, and the rewrite is undone without
anyone noticing. Record who confirmed, and treat an unconfirmed holder the same way
as an unreachable fork — an exposure that is still open.

---

## 5. Operational notes

### 5.1 Stage C gets its own change window

Do not fold Stage C into the code deployment. It is a separate change, raised
separately, with its own window and its own approval. Stage A, by contrast, belongs
*with* the deployment: it is the configuration the deployment needs.

Two reasons matter operationally. First, Stage C is irreversible, so it needs an
approval that acknowledges that; it is flagged for the deployment reviewer as an
irreversible operation in
[`../review/CRITICAL_DECISIONS.md`](../review/CRITICAL_DECISIONS.md). Second, its
credentials do not all affect a running service the same way, and the window has to
be planned for the right effect — using the terms
[Section 1.3](#13-three-kinds-of-service-impact-defined-once) defines:

| Credential | Outage | Process restart | Session invalidation |
|---|---|---|---|
| Database credentials | Yes | Yes | No |
| Google Cloud service-account key | Yes, where the proxy uses a key file | Yes | No |
| JWT signing key | **No** | Yes | **Yes** |
| PayPal webhook identifier (Stage A) | No | Yes | No |

**Two of the four cause an outage: the database credentials and the service-account
key, both because they mediate database access.** The signing key does not — it
invalidates every session while the service stays healthy, which needs support
notified rather than a maintenance page. Diagnosing any of these is far harder when
a code release is landing at the same time, which is the second reason to separate
the windows.

Sequence the window itself: collect the logs step 4 needs, then rotate credential by
credential in Section 3's order, then verify, then close.

### 5.2 Configuration must be in place before the new code starts — this is Stage A

The hardened settings module validates security-critical configuration at startup
and **fails to start** on a value that is missing, weak, placeholder-shaped or
internally inconsistent. That is deliberate — a misconfigured deployment stops
loudly instead of running in a degraded state — but it is also why this runbook is
staged, and it is the whole content of
[Stage A](#20-stage-a-provision-what-the-new-code-requires):

1. Put every required value in place **first**, in every environment. Seven settings
   have no default, and one of them, `PAYPAL_WEBHOOK_ID`, has to be created in the
   PayPal dashboard before it can be supplied at all.
2. Then start the new code.
3. Only once that deployment is verified, begin
   [Stage C](#22-stage-c-revoke-and-rotate-the-exposed-credentials).

If you start the new code first, it will not come up, and the failure will name the
setting rather than the cause. Confirm the value set before deploying, not after.

**The instruction that rotation is sequenced last applies to Stage C only.** It has
never meant deferring the provisioning of a value the deployment needs — that
reading would produce a deployment that cannot start. The reasoning behind the split
is recorded once, at row 35.7 of [`DECISION_LOG.md`](DECISION_LOG.md).

Treat [`../../.env.example`](../../.env.example) as the contract. It documents every
variable name with a safe local-development default and a non-secret placeholder
where a real value is required. Two consequences follow from that being a template
rather than a working configuration:

1. The signing-key placeholder it carries is deliberately **not** the literal
   `your_secret_key_here` and is deliberately too short to be accepted, so a
   template copied verbatim cannot start. Supplying a real key is a required
   deliberate step, not an oversight.
2. It is the one environment file that is committed, kept by the `!.env.example`
   negation. Every other environment file is ignored and must stay that way.

### 5.3 The managed secret store: storage and runtime delivery are two things

Environment variables are the delivery mechanism of last resort, not the
destination. Rotation should end with each replacement held as a new version in the
managed secret store and read from there at run time.

**Storage and delivery are separate mechanisms and they were delivered at different
times, so an operator needs to know which is which.** An earlier version of this
section described the end state as though provisioning the secret resources were
sufficient. It is not: a secret that exists in the store and cannot be read by the
workload is a secret the service cannot start on.

| Mechanism | What it is | Delivered state |
|---|---|---|
| **Storage** | Six managed secret resources — for the signing key, the database connection string, the Zillow key, the PayPal client secret, the PayPal webhook identifier and the SendGrid key — provisioned by `infrastructure/terraform/main.tf` | **Provisioned.** This was true when this section was first written |
| **Authorization** | A dedicated runtime service account, a `secretAccessor` grant on **each** of the six secrets individually rather than at the project, and a Workload Identity binding from that account to one Kubernetes service account | **Provisioned.** Added by the same round that wrote this correction; recorded at `docs/security/DECISION_LOG.md` §35.4 and §35.5 |
| **Runtime delivery** | The cluster's Secret Manager CSI add-on, a `SecretProviderClass` naming the six secrets, and workloads that mount the CSI volume and consume the synced values by reference through `envFrom` | **Provisioned**, as versioned manifests under `infrastructure/kubernetes/`. This is the part that did not exist when this section was first written, and without it the six secrets were unreachable from the workload |
| **Backend selection** | `SECRET_BACKEND` set to the managed backend in the workload's configuration | **Set.** This is what makes the delivery self-checking: the settings module refuses to start unless all six values arrived from the process environment, so a silently failed delivery is a Pod that will not start rather than a service running on the wrong values |

**The delivery prerequisite an operator must satisfy.** Rotation writes a new secret
version; nothing else in the chain changes. But the chain only functions if all four
rows above are in place for the environment being rotated, so before a rotation is
declared complete, confirm that the cluster carries the add-on, that the namespace and
service-account names in the manifests match the ones the Workload Identity binding was
created against, and that the workload restarted after the new version was written —
a mounted secret is resolved when the Pod starts, so an existing Pod continues on the
value it started with until it is replaced.

Prefer, in this order: a new version in the managed secret store; the platform's own
protected variable store for short-lived, non-critical values; and an environment
variable supplied at run time only where neither is available. Never a file in the
repository.

Where a credential can be removed rather than replaced, remove it. The
service-account key in [Section 3.2](#32-google-cloud-service-account-key) is the
clearest case: moving the proxy to ambient credentials retires that credential
class instead of rotating it, which means it never needs rotating again.

### 5.4 If something goes wrong

**Stage C cannot be rolled back, so the recovery path is forward.** There is no step
that restores a revoked credential. (Stage A is different: a value provisioned and
found wrong is simply replaced with the right one, and nothing has been destroyed.)

If a replacement does not work, do not attempt to restore the old value — it is
revoked, and re-authorizing it would reinstate the exposure you just closed. Instead:

1. Issue **another** replacement, and deliver it the same way.
2. If the service is down, treat it as an incident and prioritize delivering a
   working replacement over completing the remaining steps. Steps 3 and 4 can wait;
   an outage cannot.
3. If a history rewrite went wrong, the repository is recoverable from any
   un-rewritten clone, but the credential is not. Recover the repository, then
   continue forward with the credential.
4. Record what happened. It belongs in the step 4 review for the affected
   credential.

Do not leave a rotation half-finished. A credential that has been revoked but not
replaced is an outage; a credential that has been replaced but not removed from
history is an unfinished remediation. Both need closing out in this window.
