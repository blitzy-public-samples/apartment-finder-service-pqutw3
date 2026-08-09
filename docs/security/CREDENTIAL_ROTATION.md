# Credential Rotation Runbook

This is the operational runbook for the credentials exposed by this repository. It
is a sequence of steps to execute at a keyboard, in order, against real
infrastructure. Follow it top to bottom.

**Use this runbook when** the security remediation has been deployed and verified
and the exposed credentials must now be replaced; or at any time a credential
named in [Section 3](#3-credentials-in-scope) is suspected of having leaked again.

**Who executes it.** An operator with administrative access to the database, the
Google Cloud project, the deployment's secret store and the PayPal developer
dashboard. Some steps require more than one of these, so read
[Section 3](#3-credentials-in-scope) end to end before starting and confirm you
hold every access it needs.

---

## 1. Read this first

Two facts govern everything below. Both change how you should behave, so they come
before the steps rather than after them.

### 1.1 Rotation is sequenced last, and it cannot be rolled back

Rotation is the **final** action of this remediation. Execute it only after every
other change has been deployed and verified — the application starts, the test
suite passes, the migrations have applied and the deployment is healthy.

Rotation **cannot be rolled back.** Once a credential is revoked, the old value is
gone; there is no revert that restores it. Consequently:

1. Schedule rotation in **its own change window**, separate from the code
   deployment. Do not fold it into a release.
2. Treat it as an irreversible operation for change-approval purposes. It is
   flagged as such for the deployment reviewer in
   [`../review/CRITICAL_DECISIONS.md`](../review/CRITICAL_DECISIONS.md).
3. If a step fails, recover **forward** — see
   [Section 5.4](#54-if-something-goes-wrong).

### 1.2 Every credential here is already compromised

Do not reason about whether these values leaked. Assume they did, and act
accordingly.

The remediation removed the exposed values from the working tree. **That is not the
same as removing them from the repository.** Git history is permanent: the values
remain in every commit that ever carried them, and every clone anyone has ever
taken carries that full history. A value deleted from the current tree is still
readable by anyone holding a clone, a fork, a mirror, a backup or a CI cache.

Removal stops *future* exposure. Only revocation and rotation address the exposure
that has already happened. That is the entire reason this runbook exists.

### 1.3 Where this document sits among its siblings

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

## 2. The sequence

Every credential in [Section 3](#3-credentials-in-scope) is rotated by the same
four steps, in this order:

| Step | Action | What it achieves | Reversible? |
|------|--------|------------------|-------------|
| 1 | **Revoke** | De-authorizes the credential so it cannot be used, whatever copies of it exist | No |
| 2 | **Rotate** | Issues a replacement and returns the service to working order | No |
| 3 | **Delete from history** | Removes the value from all systems and from commit history | **No — irreversible** |
| 4 | **Review prior access** | Establishes the blast radius from access patterns before the exposure | Yes, it is read-only |

### 2.1 The four steps

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

### 2.2 Why this order is not stylistic

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
   several at once. Section 3 orders the credentials so that the two with a
   service-availability impact come first.

---

## 3. Credentials in scope

Four credentials require operator action. **These are called out separately from
the remediation's code changes precisely because none of them can be remediated by
a code change alone.** The code changes stop the values being committed again; only
the steps below address the values that were already committed.

| # | Credential | Where it was exposed | Rotating it interrupts service? |
|---|------------|----------------------|---------------------------------|
| 1 | Database credentials | `infrastructure/docker/docker-compose.yml:30` | Yes — the application cannot reach the database until the replacement is delivered |
| 2 | Google Cloud service-account key | `infrastructure/docker/docker-compose.yml:46-47` and `:49` | Yes, for any host running the Cloud SQL proxy from a key file |
| 3 | JWT signing key | `scripts/setup_dev_environment.sh:54` | No, but every issued token stops being accepted |
| 4 | PayPal webhook identifier | Not previously exposed — new configuration | No, but webhook processing does not work until it is provisioned |

Line references identify the **original** committed state of each file — the state
that persists in history. The current working tree no longer carries these values.

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
2. **Rotate.** Generate a cryptographically random replacement of at least 32
   bytes. Generate it with a tool, never by typing one:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```

   Write it to the secret store under the variable name the application reads, and
   restart the service. **Expect every existing token to stop being accepted:**
   tokens signed with the old key no longer verify, so every signed-in user is
   signed out and re-authenticates. Plan the change window accordingly and tell
   support in advance. Confirm afterwards that a fresh sign-in succeeds and returns
   a token, and that the response shape is unchanged.
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
`your_secret_key_here`, or is shorter than 32 bytes. A deployment that still
carries the placeholder will now fail loudly at startup instead of quietly issuing
forgeable tokens. Measured against the current code: that literal is rejected, a
short key is rejected, and a key generated by the command above is accepted.

### 3.4 PayPal webhook identifier

**What it is.** The identifier of the webhook subscription registered in the PayPal
dashboard. **It was not previously exposed — this is new configuration**, required
by the remediation, and it is a secret in its own right. It is included in this
runbook because it must be provisioned by an operator in the same change window and
cannot be produced by a code change.

**Provision it before the listener can verify anything.** The webhook verifier
includes this identifier in the payload it sends to PayPal to confirm a
notification's signature. Without it there is nothing to verify against, so the
route cannot distinguish a genuine PayPal notification from a forged one and
refuses the traffic instead of trusting it.

1. **Revoke.** Nothing to revoke on first provisioning; skip this step. If you are
   rotating an identifier that has already been in use, delete the old webhook
   subscription in the PayPal dashboard first, so notifications signed against it
   stop being accepted.
2. **Rotate.** Create or re-create the webhook subscription in the PayPal
   dashboard, pointing it at the deployment's webhook route and subscribing to the
   payment events the service handles. Copy the identifier PayPal issues into the
   secret store under the variable name the application reads. Restart the service.
   Confirm the certificate-host allowlist setting names only PayPal-owned hosts, as
   the verifier validates the inbound certificate host against it before use.
3. **Delete from history.** Nothing to remove for a newly issued identifier.
   Confirm only that you did not commit it: it belongs in the secret store, and the
   repository's ignore rules already exclude environment files. If you rotated an
   identifier that was previously committed anywhere, remove it as in Section 3.1
   step 3.
4. **Review prior access.** Review the webhook delivery history in the PayPal
   dashboard alongside the service's own webhook logs, and confirm the two agree on
   which notifications were delivered and accepted. Before this remediation the
   service performed no signature verification at all, so treat any subscription
   state change that predates it as unverified in origin and reconcile it against
   PayPal's record of settled payments rather than against the service's own rows.

**A note on scope while you are in the payment configuration.** This remediation
retains the PayPal hosted redirect, so no card number enters or is stored by this
service. Every value handled here is an order identifier, a plan identifier, a
client credential or a webhook identifier. Do not change the payment flow to
collect card details in the service while working through this runbook.

---

## 4. Verification

Perform these checks after rotation. They are manual because no automated gate can
confirm them — each asks whether an operator did something, or whether a value
placed outside the repository is the right value.

Record the outcome of every check. An unrecorded verification is indistinguishable
from a skipped one.

### 4.1 Confirm the documented order was followed

For each credential, confirm the four steps ran in order, and **specifically that
revocation preceded any history rewrite.** Check the timestamps rather than asking:
compare the revocation time recorded at the issuing system against the commit time
of any rewrite. If a rewrite happened first, the credential was live in every
outstanding clone for the interval between the two, and that interval is an
exposure window you must record and assess in the step 4 review.

### 4.2 Confirm no secret value remains in the current tree

Search the working tree for each rotated value and for the patterns that carried
them. Confirm zero results. Search the full history separately — the working tree
being clean says nothing about history, which is the point of step 3.

Confirm too that no replacement value was introduced anywhere in the tree while
rotating. It is a common and quiet mistake to remove an old credential and commit
the new one beside it.

### 4.3 Confirm the ignore rules cover every path where a secret previously lived

**No `.gitignore` existed at any level of this repository before this
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

Confirm each replacement is supplied from the secret store and is **not** present in
any committed file.

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

Confirm the deployed payment mode agrees with the deployment's environment name,
and that the payment API base agrees with the mode. A production environment
configured against sandbox payment settings is refused at startup by design.

**Exercise this guard in a non-production deployment first.** Confirm there that a
mismatched pair fails to start and that a matching pair starts cleanly, then apply
the configuration to production. Discovering the guard for the first time during a
production start is avoidable.

### 4.6 Post-rotation smoke checks

Finally, confirm the deployment is genuinely serving on the rotated credentials
rather than on a cached connection or a stale process:

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

---

## 5. Operational notes

### 5.1 Rotation gets its own change window

Do not fold rotation into the code deployment. It is a separate change, raised
separately, with its own window and its own approval.

Two reasons matter operationally. First, rotation is irreversible, so it needs an
approval that acknowledges that; it is flagged for the deployment reviewer as an
irreversible operation in
[`../review/CRITICAL_DECISIONS.md`](../review/CRITICAL_DECISIONS.md). Second, two of
the four credentials interrupt service when they change — the database credential
and the signing key — and diagnosing an interruption is far harder when a code
release is landing at the same time. Separating them means that if something breaks,
you already know which change caused it.

Sequence the window itself: collect the logs step 4 needs, then rotate credential by
credential, then verify, then close.

### 5.2 Configuration must be in place before the new code starts

The hardened settings module validates security-critical configuration at startup
and **fails to start** on a value that is missing, weak, placeholder-shaped or
internally inconsistent. That is deliberate — a misconfigured deployment stops
loudly instead of running in a degraded state — but it makes ordering matter:

1. Put every required value in place **first**, in every environment.
2. Then start the new code.

If you start the new code first, it will not come up, and the failure will name the
setting rather than the cause. Confirm the value set before deploying, not after.

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

### 5.3 The target state is a managed secret store

Environment variables are the delivery mechanism of last resort, not the
destination. The infrastructure change set provisions managed secret resources for
the sensitive values — the signing key, the database connection string, the Zillow
key, the PayPal client secret, the PayPal webhook identifier and the SendGrid key —
so rotation should end with each replacement held as a new version in the secret
store and read from there at run time.

Prefer, in this order: a new version in the managed secret store; the platform's own
protected variable store for short-lived, non-critical values; and an environment
variable supplied at run time only where neither is available. Never a file in the
repository.

Where a credential can be removed rather than replaced, remove it. The
service-account key in [Section 3.2](#32-google-cloud-service-account-key) is the
clearest case: moving the proxy to ambient credentials retires that credential
class instead of rotating it, which means it never needs rotating again.

### 5.4 If something goes wrong

**Rotation cannot be rolled back, so the recovery path is forward.** There is no
step that restores a revoked credential.

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
