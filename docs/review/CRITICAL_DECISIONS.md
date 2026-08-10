# Critical Decision Review

This is the Rule 3 review artefact for the `apartment-finder-service` security
remediation. It lists the five highest-risk decisions made during the work, ordered
highest risk first, and assigns each to a named reviewer together with the specific
checks that reviewer should perform.

Its scope is deliberately narrow. The reasoning behind every decision below — the
alternatives weighed, the argument for the choice made, and the risk accepted — is
recorded once in [`../security/DECISION_LOG.md`](../security/DECISION_LOG.md), which
this document defers to rather than duplicates. Every entry names the row of that log
which owns its full argument. What this document adds is the assignment of review
responsibility and the checks that discharge it.

Rule 3 requires that irreversible operations, authorization decisions, and any
assumption that resolved an ambiguity in the request always be called out. All three
categories are present in this work, and each entry below is labelled with the
category or categories it satisfies.

---

## Summary

| # | Decision | Risk | Rule 3 category called out | Reviewer |
|---|----------|------|----------------------------|----------|
| 1 | Rotate the exposed credentials rather than only removing them from the working tree | **High** | Irreversible operation | DevOps |
| 2 | Seed exactly one administrator through a separate migration revision | **High** | Authorization decision | Security |
| 3 | Restrict `POST /listings/` to administrators | **High** | Authorization decision; breaking change | API/Integration |
| 4 | Verify PayPal webhook signatures with a certificate-host allowlist | **High** | Authorization decision; ambiguity-resolving assumption | Security |
| 5 | Accept eight residual dependency advisories to hold the Python 3.9 pin | **Medium** | Ambiguity-resolving assumption | DevOps |

**Five entries, and exactly five.** The numbered sections below are the five decisions
and nothing else; the review-sequencing note that follows them is deliberately
unnumbered so that it cannot be read as a sixth. Entries 2 to 5 are reviewed against the
change set as delivered. Entry 1 is reviewed last, for the reason given in
[Review sequencing](#review-sequencing-and-companion-artefacts).

**What was restored in this revision, recorded rather than silently applied.** An earlier
revision promoted the runtime-pin decision from fifth to second and raised it from Medium
to High, added a subsection arguing that ranking, and pushed the advisory acceptance it
displaced into an appendix that carried its own Decision, Rationale and Reviewer sections
— which made it a sixth entry in everything but its heading. The order and the risk
framing here are the Agent Action Plan's own, entry for entry, and the appendix is folded
back into entry 5 as that entry's two consequences. Nothing is dropped: the retirement of
the pinned managed-functions runtime is the second consequence of the same decision, is
registered as open item **O-3** and marked blocking, and carries checks 1 to 4 of entry 5.
Row 91.9.1 of the decision log owns this restoration and the alternatives to it.

---

## 1. Rotate the exposed credentials rather than only removing them from the working tree

- **Risk level:** High
- **Rule 3 category:** irreversible operation
- **Reviewer:** DevOps

### Decision and alternatives

Every credential this repository exposed is treated as already compromised and is
rotated, following the ordered runbook at
[`../security/CREDENTIAL_ROTATION.md`](../security/CREDENTIAL_ROTATION.md). The
runbook's scope is **five** credentials: the database credentials, the Google Cloud
service-account key, the JWT signing key, the listing-provider (Zillow) API key, and
the PayPal webhook identifier, which was not previously exposed but is new secret
configuration an operator must provision in the same window.

The alternative was to delete the values from the current tree and stop there. A
second and narrower alternative was to scope the rotation to the credentials that
were **committed as literals**, which would have covered the first three and omitted
the listing-provider key. That is rejected: a credential written into a request URL
and then printed to standard output is disclosed just as effectively as one written
into a committed file — only the store that holds the disclosure differs, and the
handling has to differ with it.

The change set itself performs only the tree removal and the code changes that stop
future exposure. Revocation and rotation are operator actions, deferred to the
runbook and sequenced last. Row 16.6 of the decision log owns that reasoning.

### Rationale

`infrastructure/docker/docker-compose.yml:30` committed a `DATABASE_URL` literal
carrying an embedded username and password. It was supplied to the application on
every container start, so it was the working credential for the deployed service and
not merely an example. Lines `:46-47` bind-mounted a host `./secrets` directory into
the container and `:49` named the service-account key as the credentials path; the
file's own trailing comment at `:65-67` instructed the reader to place that key file
into `./secrets`, so the arrangement functioned only when a credential was present in
the repository tree.

Separately, `scripts/setup_dev_environment.sh:54` wrote the literal placeholder
`your_secret_key_here` as the signing key into every developer's environment file.
That is the upstream origin of the weak-signing-key finding, and it is the exact
string the hardened settings module now refuses at startup. Line `:55` wrote a
credentialed connection string, and `:69` hardcoded a database password inside a
`CREATE USER` statement.

Separately again, `backend/app/services/zillow_service.py:15-19` placed the
listing-provider API key in the request's **query parameters**, so the key
travelled inside the request URL and was recorded by the provider's access logs and
by any proxy on the path. Line `:27` then printed the exception text with a bare
`print()`, and the HTTP library embeds the full request URL in its exception
messages — so one upstream failure wrote the key to standard output, and from there
to the container log and to whatever store collects it. There was no logging
framework, so there was no interception point at which the value could have been
redacted. The remediation moved the key into a header, added a request timeout and
replaced the `print()` with the redacting structured logger; none of that reaches
the records already written.

Removal addresses only future exposure, and **where the exposure lives differs by
credential.** Git history is permanent: each committed value remains in every commit
that carried it, and every clone, fork, mirror, backup and continuous-integration
cache taken since carries that history. The listing-provider key was never
committed, so its exposure sits in log archives, log-aggregation indexes, proxy logs
and the provider's own access logs instead — which is why its step 3 is a search of
the log estate rather than of the repository. Only revocation and rotation address
the exposure that has already happened, in either shape.

### Reviewer persona and exactly what to check

**DevOps.** For each credential in the runbook's scope:

1. Confirm the four documented steps ran in this order: **revoke, rotate, delete from
   history, review prior access.**
2. Confirm specifically that **revocation preceded any history rewrite.** Verify this
   from timestamps rather than by asking — compare the revocation time recorded at the
   issuing system against the commit time of the rewrite. A rewrite that ran first
   left the credential live inside every outstanding clone for the interval between
   the two; record that interval as an exposure window and assess it in the
   review-prior-access step.
3. Confirm rotation was executed only after every other change had been deployed and
   verified, and that it ran in its own change window rather than folded into a
   release. It cannot be rolled back, so the approval must acknowledge that.
4. Confirm no replacement value was committed anywhere in the tree while rotating, and
   that no rotated value remains in the working tree.
5. Confirm the root `.gitignore` covers every path a secret occupied or was directed
   to — including the `secrets/` directory the bind-mount used and the credential file
   named at `docker-compose.yml:49`.
6. Confirm the scope is **all five** credentials and not only the three that were
   committed as literals. Specifically, for the listing-provider (Zillow) API key:
   that it was revoked in the provider's developer console rather than merely
   supplemented by a second key; that the replacement is delivered from the secret
   store and reaches the service as a request **header**, never a query parameter;
   that the log estate holding the old key — container logs, the aggregation service
   and its search indexes, proxy access logs, build logs and developer machines — has
   been purged or has a recorded expiry date; and that the provider's usage logs for
   the old key were reviewed for volume, source addresses and endpoints that
   scheduled ingestion cannot explain.
7. Confirm the date the last log record containing the old listing-provider key
   leaves the estate. **If that date is in the future, the rotation is complete but
   the exposure is not**, and the approval record should say so rather than closing
   the item.

[`../security/CREDENTIAL_ROTATION.md`](../security/CREDENTIAL_ROTATION.md) is the
authoritative runbook, its Section 4 is the verification checklist and its Section
4.7 covers check 6 above; work from those rather than from this summary. Record the
outcome of every check, because an unrecorded verification is indistinguishable from
a skipped one.

---

## 2. Seed exactly one administrator through a separate migration revision

- **Risk level:** High
- **Rule 3 category:** authorization decision
- **Reviewer:** Security

### Decision and alternatives

The single administrative role grant lives in its own migration revision,
`backend/migrations/versions/0002_seed_single_admin.py` — separate from the additive
schema revision, idempotent, explicitly logged, and asserting as a post-condition that
exactly one administrator exists. The alternatives were to grant the role inline in
the additive revision that adds the `role` column, to grant it from application logic
at startup or on a designated first registration, or to grant it by hand in each
environment with no revision at all.

Row 34.3.2 of the decision log owns the full argument; its sections 19 and 25 record
the implementation detail and one later reversal.

### Rationale

In the tree this work started from, `backend/app/db/models.py` declared `User` with
only `id`, `email`, `hashed_password`, a non-nullable `created_at` and `last_login`,
plus its two relationships. **There was no `role` column at all**, so no authorization
decision had anywhere to read a role from, and every protected route resolved through a
dependency that answered only whether the caller was authenticated. `Subscription` in
the same module likewise declared only `id`, `user_id`, `start_date`, `end_date`,
`status` and its relationship — no plan, amount, currency or order-identifier column,
so no ownership check against a payment was possible either.

Separating the grant into its own revision is itself the audit control. One revision
carries one log record, one asserted post-condition and one downgrade, so a reviewer
can answer who was granted privilege, when, and by which statement, from a single
artefact. In the delivered tree `User.role` carries a server default of `registered` in
`backend/app/db/models.py`, which is what allows the additive revision to land every
pre-existing account on the default role while granting nothing. It is named as a construct
rather than by line number deliberately: the two references this document previously carried
for it — `:19` and `:37` — each selected a declaration other than the column once the
module grew, the first the workload-index tuple and the second the open-intent predicate. A
construct name cannot drift the way a line number does. Line numbers elsewhere in this
Rationale are baseline locations, per this document's convention.

### Reviewer persona and exactly what to check

**Security.**

1. Confirm **exactly one** account holds the administrative role after migration, and
   that the seed revision asserts this as a post-condition rather than leaving it to
   be checked by hand.
2. Confirm every other account carries the default role `registered`.
3. Confirm a registration request carrying a `role` field still yields `registered` —
   the negative proof that no automatic escalation path exists.
4. Confirm the additive revision
   `backend/migrations/versions/0001_add_rbac_and_subscription_columns.py` grants no
   administrator at all, and that its downgrade reverses exactly what its upgrade did to
   the database it found. **There are two branches and both need reading, because they
   remove different things.** On a database that already held the six tables preceding
   this work, the upgrade appends columns and the downgrade removes only those — the
   three `users` columns, the four `subscriptions` columns and the order uniqueness —
   leaving those six tables and every row in them in place. On an empty database the
   upgrade creates the tables itself, records which ones it created in
   `alembic_0001_created_tables`, and the downgrade drops exactly that recorded set, so
   reversing the whole chain there leaves nothing but Alembic's own version table.
   Reading only the first branch is what makes the reversal look narrower than it is.
5. Confirm the seed revision's downgrade demotes the seeded account back to
   `registered`.
6. Confirm the revision is idempotent by applying it twice and re-reading the addresses
   holding the administrative role — the post-condition is that ordered list equalling
   exactly the one address the revision names, not a count, so an extra administrator at
   another address fails it.
7. Confirm no application code path can write the administrative value, so that adding
   a further administrator remains a deliberate migration or an out-of-band action
   rather than a self-service one.

---

## 3. Restrict `POST /listings/` to administrators

- **Risk level:** High
- **Rule 3 categories:** authorization decision; breaking change
- **Reviewer:** API/Integration

### Decision and alternatives

`POST /listings/` moves from reachable by any authenticated account to administrators
only, enforced through the same centralized authorization dependency every other
guarded route uses. **This is the one intentional breaking change in the
remediation.**

The alternatives were to leave the endpoint open and rely on content validation to
constrain what may be written, to introduce a listing-ownership model so an account
could write and amend only its own rows, or to gate on the `premium` role instead.
Row 34.3.1 of the decision log owns all three and the reason each was rejected.

### Rationale

`backend/app/api/endpoints/listings.py:17-18` guarded the write route with
`current_user: User = Depends(get_current_user)` and nothing further, so
authentication alone granted write access to the shared listings corpus that every
user of the service reads. Registration is self-service, so any account could inject
or manipulate corpus content. No amount of input validation closes an authorization
gap; only a function-level authorization control does.

Two supporting findings in the same file were closed alongside it. Line `:13` declared
`limit: int = 100` with a default but no maximum, permitting single-request extraction
of the entire corpus. Line `:23` constructed
`ListingModel(**listing.dict(), owner_id=current_user.id)` — a mass assignment that
additionally named a column the `Listing` model does not define.

**The listings read endpoint remains publicly reachable without authentication.** That
is a frozen requirement; only the write route's authorization level changed.

**Blast radius, measured rather than estimated.** No module under `frontend/src/**`
calls this endpoint. The corpus is populated by the background ingestion task, which
writes through the ORM rather than through the HTTP route, so the ingestion workflow
is unaffected. The practical exposure is therefore limited to any external or
operational client that is not present in this repository — and no inventory of such
clients exists here to consult, which is precisely why this change is surfaced
explicitly rather than introduced silently.

### Reviewer persona and exactly what to check

**API/Integration.**

1. Confirm every consumer of `POST /listings/` outside `frontend/src/**` has been
   identified and notified. No inventory of such consumers exists in this repository,
   so this check cannot be completed from inside it.
2. Confirm the change appears in the release notes as a breaking change, named by
   endpoint and by the role now required.
3. Confirm it is stated in all five of the places it is meant to appear: the plan's own
   transformation mapping, this document,
   [`../security/DECISION_LOG.md`](../security/DECISION_LOG.md), the project
   `README.md`, and the executive presentation's risk slide.
4. Confirm `GET /listings/` still answers successfully with no authorization header, so
   that the read endpoint's public reachability was not restricted alongside the write
   endpoint.
5. Confirm the refusal is asserted for every non-administrative principal in the
   route-and-principal grid — 45 assertions across 9 routes and 5 principals —
   including the anonymous principal.
6. Confirm any deployment that needs corpus writes from a non-administrative operator
   grants that operator the role deliberately, rather than the endpoint being reopened.

---

## 4. Verify PayPal webhook signatures with a certificate-host allowlist

- **Risk level:** High
- **Rule 3 categories:** authorization decision; ambiguity-resolving assumption
- **Reviewer:** Security

### Decision and alternatives

Inbound PayPal webhook notifications are trusted only after signature verification,
and the certificate host is validated against a configured allowlist **before** the
certificate URL is used or transmitted. The alternative was to verify the signature
without restricting the host.

**The ambiguity this resolved:** the request called for a webhook endpoint without
specifying which of PayPal's two documented verification methods to use. Rows 6.5 and
34.4.1 of the decision log own the choice made and the decision to mount the listener
beneath the existing `/subscriptions` prefix.

### Rationale

`backend/app/services/paypal_service.py:11` read
`"mode": "sandbox",  # Change to "live" for production` — a source comment as the only
production control. Lines `:41-47` defined
`execute_payment(payment_id: str, payer_id: str)`, taking both identifiers from the
caller and performing no ownership lookup, which is the canonical
broken-object-level-authorization shape. No webhook route and no signature
verification existed anywhere in the repository, so there was no mechanism by which
the service could distinguish a genuine PayPal notification from a forged one.

The host allowlist is load-bearing rather than merely prudent. The certificate URL
arrives in an attacker-controllable request header, so an unrestricted verifier can be
pointed at an attacker-hosted certificate and made to accept a payload the attacker
signed themselves. Verification without the allowlist would offer the appearance of
assurance rather than assurance, which is a worse position than none because it
invites reliance.

The listener is necessarily unauthenticated, because the provider presents no user
token. That is exactly why its signature verification, its host allowlist and its
replay defence are the controls themselves rather than a supplement to one. The hosted
redirect is retained, so no card number enters or is stored by this service.

### Reviewer persona and exactly what to check

**Security.**

1. Confirm the certificate host is validated against the allowlist **before** the
   certificate URL is fetched or forwarded. Verify this by reading the order of
   operations in the verification function, not by observing that a check exists
   somewhere in it.
2. Confirm the allowlist contains only PayPal-owned hosts, and that it is supplied as
   configuration rather than as a literal embedded in the verification path.
3. Confirm a notification with a tampered signature is rejected and leaves **no state
   change** — no subscription row created or amended, and no entitlement granted.
4. Confirm a repeated transmission identifier is rejected, so that a replayed
   notification cannot be processed twice and each event is processed exactly once.
5. Confirm a notification missing any required header is rejected rather than treated
   as unverifiable but acceptable.
6. Confirm a success response is emitted only after verification and processing have
   both completed, never before.
7. Confirm the deployed payment mode matches the deployed environment name, and that a
   production environment paired with sandbox credentials fails at startup rather than
   transacting. Exercise this guard in a non-production deployment first.
8. Confirm payment capture is bound to the owning user through a server-side lookup on
   the stored order identifier, rather than by comparing an identifier the client
   supplied.

---

## 5. Accept eight residual dependency advisories to hold the Python 3.9 pin

- **Risk level:** Medium
- **Rule 3 category:** ambiguity-resolving assumption
- **Reviewer:** DevOps

### Decision and alternatives

One decision with two consequences. Holding the interpreter pin puts a set of library
fixes out of reach, and it puts a hosting platform out of reach. Both follow from the same
constraint, and both are recorded here rather than split across two entries.

#### Consequence A — the hosting platform the pin makes unavailable

The provider retired the Python 3.9 runtime of its managed serverless functions product
on **5 April 2026**. Under that provider's runtime-support policy, a retired runtime can
no longer be used to create or update a function after that date, and existing
deployments on it become liable to be disabled. `infrastructure/terraform/main.tf:384`
declares such a function and `scripts/deploy.sh:768` deploys one — pin sites 3 and 4 of
the table below.

**Both are withheld rather than removed.** `google_cloudfunctions_function.function` and
its invoker binding each carry `count = var.cloud_function_deployment_authorized ? 1 : 0`,
whose default is `false`, and `scripts/deploy.sh` returns from its function step unless
`CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED=true`. So an apply and a release reach the
decommissioned runtime only once a release owner has decided that conflict: the
configuration stays appliable because the resource is not created, the pin stays declared
where a reviewer expects to find it, and the escalation is stated in the configuration
beside the resource. An earlier revision of this entry recorded both as **removed**, which
is not what was delivered; row 91.9.1 of the decision log records the correction.

**The function this gates is real.** `infrastructure/functions/health/main.py:79` defines
`hello_world`, the entry point `var.cloud_function_entry_point` names; the archive is
content-addressed from that directory by a `data "archive_file"` rather than named as a
`function-source.zip` that exists nowhere; and the placeholder display name is gone. What
is unresolvable inside this scope is the runtime identifier itself, which the pin forbids
changing.

The alternatives, all rejected — row 35.1 of the decision log owns the argument:

1. **Advance the function's runtime** and keep the resource. Unavailable: the pin is a
   hard constraint, and the code itself would break, per the Rationale below.
2. **Keep the resource ungated on the retired runtime** and record the decommission as a
   known issue. Rejected: an apply would then fail at the provider, which is the defect
   rather than a disclosure of it.
3. **Comment the resource out.** Rejected: the same broken claim in a form no check reads.
4. **Migrate to a second-generation function or a container-hosted service.** Rejected as
   a platform introduction this work has no authorization to make.

**The residual authorization exposure.** Withholding a resource does **not** revoke a
binding a previous apply or deploy already granted. If a managed function still exists in
a live project, an anonymous invoker binding on it may still be live. This is why
`scripts/deploy.sh` performs an explicit, idempotent revocation of both anonymous
principals rather than relying on the resource not being created.

**The ingestion workload does not depend on it.** `run_listing_updater()` is reached by
the Kubernetes CronJob at `infrastructure/kubernetes/65-ingestion-cronjob.yaml`, running
on the same `python:3.9-slim` backend image, so nothing periodic waits on the gated
resource. That was re-verified **by execution**: the exact command the job runs was run
under CPython 3.9.25 and exited 0.

**Where this consequence is tracked.** It is registered as open item **O-3**, marked
blocking, in [`../security/RESIDUAL_RISK.md`](../security/RESIDUAL_RISK.md), and checks 1
to 4 below discharge it. Row 91.9.1 of the decision log owns the reasoning for carrying it
here rather than as a separate entry.

#### Consequence B — the dependency advisories

Seven advisories **against the runtime manifest** — `backend/requirements.txt`, the
only manifest a deployed image installs — are accepted as residual risk, each with a
named compensating control, rather than advancing the Python interpreter so that their
fixes become installable. The alternative was to advance the runtime.

**Read the count precisely: seven is the runtime figure, not the total.** The pipeline
audits **two** manifests and suppresses **eight** identifiers in total, in two
separate steps with two separate registers:

Read as a total, that is **eight accepted advisories**: seven for
`backend/requirements.txt`, the only manifest a deployed image installs, and
one for `backend/requirements-dev.txt`, which reaches no deployed artifact.

| Register | Manifest | Count | Authority | Reaches a deployed artifact? |
|----------|----------|-------|-----------|------------------------------|
| Runtime | `backend/requirements.txt` | 7 | [`../security/RESIDUAL_RISK.md`](../security/RESIDUAL_RISK.md) | Yes — the backend image installs this manifest |
| Development | `backend/requirements-dev.txt` | 1 | the *Development register* of the same file | No — the test framework only |
| — | `backend/requirements-audit.txt` | not audited | *The audit instrument's own tree*, same file | No — the audit instrument only |

The two audited sets are disjoint, and both are registered in the residual-risk
document, which carries a section per audited manifest. Every other figure quoted
elsewhere in this document — the 19-to-7 reduction, the "three packages" — is a
**runtime** figure.

**A reviewer should not read either set as the whole.** Seven sit in the runtime
manifest, which the deployed image installs, so each carries a control arguing that the
specific defective code path is never taken. One sits in the development manifest — the
test framework, which no deployed process installs — so its control is that absence.

**The total was fourteen until this round, and six of that fourteen were not this
project's.** `pip-audit` was declared in the development manifest, so auditing that
manifest reported the scanner's own dependency tree — `msgpack` and `filelock` through
`CacheControl[filecache]`, and `requests` with `urllib3` beneath it. The instrument now
has a manifest of its own that no audit reads, so those six are reported nowhere and
suppressed nowhere: no `--ignore-vuln` flag in either workflow names one of them. That
is a change to what is measured rather than to what is ignored, and the measurement is
recorded in the register. Row 94.1.1 of the decision log owns the choice and its
alternatives.

**The ambiguity this resolved:** the instruction that the dependency audit report zero
advisories stood against the instruction never to advance the runtime. Row 1.9 of the
decision log owns the choice, and
[`../security/RESIDUAL_RISK.md`](../security/RESIDUAL_RISK.md) is the authoritative
register for the runtime seven, carrying the measurement behind every compensating
control.

### Rationale

The pin is load-bearing in five independent places — four version declarations and one
code-level constraint — and the decisive one is code rather than configuration.
`backend/app/tasks/listing_updater.py:329` applies `@asyncio.coroutine` to an
`async def`; that decorator was removed in Python 3.11, so the codebase itself would
break on a newer interpreter. The pin is therefore a property of the code and not merely
of its configuration. All five sites, as delivered:

| # | Pin site | What pins it |
|---|----------|--------------|
| 1 | `infrastructure/docker/Dockerfile.backend:1` | `FROM python:3.9-slim` |
| 2 | `.github/workflows/ci.yml:108` | `python-version: '3.9'` |
| 3 | `infrastructure/terraform/main.tf:384` | `runtime = "python39"` |
| 4 | `scripts/deploy.sh:768` | `--runtime python39` |
| 5 | `backend/app/tasks/listing_updater.py:329` | `@asyncio.coroutine` |

[`../security/RESIDUAL_RISK.md`](../security/RESIDUAL_RISK.md) carries the same five-site
table and is the single authoritative inventory; row 91.2.1 of the decision log records
the measurement behind it, and supersedes an intermediate count of three that §82.27.1
published while sites 3 and 4 stood deleted rather than withheld. A reviewer should read
five sites there and here alike.

The deployment script's site is cited for its retained runtime flag specifically. It
sits inside the `gcloud functions deploy` invocation that this work rewrote, two lines
above the `--no-allow-unauthenticated` that replaced the `--allow-unauthenticated` this
change removes — so it is a retained value inside a changed command, not an untouched
line.

**These five line numbers drift whenever the files around them change, and they have
drifted before.** They are therefore not maintained by hand:
`test_the_runtime_pin_is_still_carried_at_every_site` asserts that each file still
carries its construct, and `test_every_documented_pin_site_line_is_correct` asserts
that each **line number quoted in this table** still holds it. A future edit that moves
a pin fails the second of those, so this table cannot silently go stale again.

Every line number above is read from the working tree this document is committed
against, and `backend/tests/security/test_documentation_citations.py` re-reads each one
on every test run, so a citation that drifts fails the build instead of misdirecting a
reviewer. The five references this document previously carried — lines 10, 2, 19, 99 and
24 — described the tree this work started from. A later revision's numbers for sites 2
to 5 — 88, 386, 669 and 370 — described the tree before the delivery paths, the gate
workflow and the ingestion module grew around them, which moved four of the five sites
again; and site 4 moved once more, from 775, when an unread constant was removed from the
release script above it. Every generation is corrected here, and none is maintained by
hand.

Every accepted advisory's fix version lies above the highest release installable under
the pin, and each defect was proven unreachable in this codebase before it was
accepted. Of the runtime seven, five are against `starlette` 0.49.3, one against
`python-dotenv` 1.2.1, and one against `click` 8.1.8; the register names each
identifier with its unreachable fix version and the evidence behind its control.

The dependency position still improves substantially. **Runtime** advisories fall from
19 across 7 packages to 7 across 3 — a 63% reduction — and static-analysis findings at
Medium or above fall from 1 to 0.

### Reviewer persona and exactly what to check

**DevOps.** Checks 1 to 4 concern the hosting platform; checks 5 to 10 concern the
advisories.

1. Confirm the managed-runtime function resource is created by neither delivery path
   without an explicit authorization. `count` on
   `google_cloudfunctions_function.function` and on its invoker binding must read
   `var.cloud_function_deployment_authorized ? 1 : 0`, that variable must default to
   `false`, and the function step of `scripts/deploy.sh` must return before
   `gcloud functions deploy` unless `CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED=true`. An
   absence sweep should report zero occurrences of the placeholder display name
   "My function" and of any source archive that is not produced from
   `infrastructure/functions/`.
2. **Confirm, against the live project rather than against this repository, whether a
   managed function still exists** — and if one does, that its invoker role carries
   neither `allUsers` nor `allAuthenticatedUsers`. Withholding the resource here does not
   revoke a binding already granted; only the revocation step does. Confirm that step in
   `scripts/deploy.sh` names both anonymous principals, and that its default function
   name matches whatever a legacy function in your project is actually called.
3. Confirm the ingestion workload runs on the pinned interpreter independently of the
   gated function: the CronJob at
   `infrastructure/kubernetes/65-ingestion-cronjob.yaml`, on the backend image whose base
   pins CPython 3.9, with a completed run in its history. Confirming the manifest is
   delivered is not the same as confirming it is applied, and only the second answers
   whether the listings corpus refreshes.
4. Confirm open item **O-3** is understood as a present blocker rather than a future
   deadline, and that no runbook or release note implies the gated function is
   deployable as configured. Every other component is unaffected: the backend service
   carries its own pinned interpreter in its image and has no equivalent lifecycle gate.
5. Confirm the dependency audit run against **each manifest separately** — not against
   the installed environment, which conflates the audit tool's own dependency tree with
   the application's. `pip-audit -r backend/requirements.txt` must report exactly the
   seven the register's *Runtime register* names; `pip-audit -r backend/requirements-dev.txt`
   must report exactly the one its *Development register* names. Eight
   suppressions across the two steps is the expected total, and neither step may
   suppress an identifier belonging to the other's register. `backend/requirements-audit.txt`
   is audited by neither step, which is what keeps the scanner's own dependency tree
   out of both counts.
6. Confirm each of the eight has a compensating control or a recorded reason it
   needs none. Each of the runtime seven has a compensating control that is genuinely
   in place rather than a stated intention, checked against the evidence recorded in
   the register. The development one carries no compensating control by design: it
   reaches no deployed artifact, which is the control.
7. Confirm both continuous-integration guards are wired, so that the acceptance cannot
   silently decay:
   - **Guard 1**, asserting the omitted `python-multipart` package stays absent. Its
     reintroduction would return six advisories and silently lapse the control
     recorded for PYSEC-2026-249.
   - **Guard 2**, the eight-pattern reachability guard over Python files under
     `backend/`. It reads zero today.
8. Confirm both guards fail the build rather than merely report, by inspecting how each
   step's exit status is handled.
9. Confirm all five pin sites still carry the pinned runtime, including
   `scripts/deploy.sh:768`, where the runtime flag is retained while
   `--allow-unauthenticated` is removed in favour of `--no-allow-unauthenticated`. The
   two assertions named above cover both the construct and the line number quoted for
   it, so this check is a matter of reading their outcome rather than of counting by
   hand.
10. Confirm the register's reproduction instructions still yield the same seven
    advisories on the pinned interpreter, so that the acceptance rests on a measurement
    a reviewer can repeat rather than on an assertion.

---

## Review sequencing and companion artefacts

**Review sequencing.** Review entries 2 to 5 against the change set as delivered.
Entry 1 is reviewed last, because the operation it covers is performed last: credential
rotation cannot be rolled back, so it is executed only after every other change has
been deployed and verified, in its own change window. Reviewing it any earlier reviews
an intention rather than an action.

**The single break in compatibility.** Entry 3 is the only intentional breaking change
in this work. Everything else preserves existing behaviour by construction — the login
response shape, every route path, every router prefix, the public reachability of the
listings read endpoint, and the verifiability of every stored password hash.

**Findings outside the stated scope.** Security-relevant issues were discovered outside
the scope of this work. Every one is flagged and awaiting confirmation or an operator
action; none is fixed here, and none is a review item for this document. §35.1 of the
decision log enumerates them item by item and is the only place the inventory lives. It
expands the bare count at row 34.6.3, which remains the decision that none of them is
fixed: one of the original items closed because the tree changed rather than because
anything was decided, and four operator-owned items were added by the infrastructure and
release-path round. Row 91.8.1 confirms that the position still holds against the
delivered tree, and §91.1 records the two that a later round changed in breach of it and
this round reverted. No total is quoted here, because a total held in two documents drifts
the moment either changes.

**Open items a reviewer must not read as delivered.** Distinct from those ten, and
listed here because a reviewer signing off on the five decisions above could otherwise
reasonably infer that everything not named as a risk was delivered and working. Nine
items were **deliberately left open**, each under a clause of the Agent Action Plan that
forbade closing it within this scope. None is a defect in delivered code; each is a
platform date, a cross-layer gap, an unverified external contract, a missing prerequisite
or an operator action. The full
statement of each — what is open, the governing clause, what an operator must do and how
it is detectable — is in
[`../security/RESIDUAL_RISK.md`](../security/RESIDUAL_RISK.md) under *Open items that are
not dependency advisories*, and the reasoning is logged in §36.6 of the decision log.
Two of the eight were restated after the delivered tree contradicted them, at log rows
91.3.1 and 91.3.2.

| # | Open item | Governing clause | Where it is reviewed |
|---|-----------|------------------|----------------------|
| O-1 | The exposed credentials are not rotated and stay reachable in history | AAP §0.10.3 sequences rotation last | **Entry 1 above** |
| O-2 | CPython 3.9 is end-of-life and stays pinned at five sites | AAP §0.1.2 hard pin | **Entry 5 above** |
| O-3 | The Cloud Function's `python39` runtime is **already decommissioned**, so that function cannot be created or updated as configured | AAP §0.1.2 hard pin | **Entry 5 above**, checks 1 and 2 |
| O-4 | The provisioned database is PostgreSQL 13, past end of life | AAP §0.9.2 held for confirmation | Not a decision here |
| O-5 | The browser client posts to a login path this backend does not serve and reads fields it does not return | AAP §0.9.2 and §0.1.2 together foreclose both sides | Not a decision here |
| O-6 | The client drives the provider's subscription product while the backend implements orders | AAP §0.9.2 and §0.1.2 | Not a decision here |
| O-7 | The frontend builds on an end-of-life Node major with one undeclared dependency. The Kubernetes workload objects the deployment updates **are** now versioned here, under `infrastructure/kubernetes/` | AAP §0.9.2 excludes the frontend manifest | Not a decision here |
| O-8 | The ingestion schedule is delivered as a Kubernetes CronJob. It must not be enabled until O-9 is closed, because an hourly pass against an unverified adapter fails every hour rather than once | AAP §0.9.2 excludes feature additions, so the schedule exists only to replace a decommissioned runtime | **Entry 2 above**, checks 3 and 4 |
| O-9 | The listing provider's request shape, parameter names and response fields were never verified against a provider, so the adapter may not work against a real one | AAP §0.6.1.2 authorises three security changes to that adapter and no more; §0.9.2 reports findings outside scope rather than fixing them | **Entry 2 above**, check 5 |

Three of these carry consequences sharp enough that a reviewer should confirm them
explicitly rather than take them on trust, because in each case the delivered system
does less than an unqualified reading of this work would suggest.

- **O-3 is a present blocker, not a future deadline.** The decommission date the review
  recorded has passed. Confirm the Cloud Function is understood as undeployable as
  configured, that the gate keeping it out of every plan and every release is closed by
  default, and that no runbook or release note implies otherwise. Every other
  component is unaffected: the backend service carries its own pinned interpreter in its
  image and has no equivalent lifecycle gate.
- **O-5 and O-6 together mean the browser client cannot authenticate against this
  backend or complete a payment through it.** This is the largest unclosed gap in the
  delivery. It is not a security weakness — the backend refuses those requests rather
  than mishandling them — but it does mean the system is not end-to-end functional
  through the browser, and the integration reviewer for entry 3 is the right person to
  confirm that this is understood and scheduled rather than discovered later.
- **O-8 and O-9 together mean the listing corpus has a schedule but not a verified
  provider.** An earlier revision of this document said no ingestion trigger existed and
  sent a reviewer to solve that. It does exist — `infrastructure/kubernetes/65-ingestion-cronjob.yaml` —
  and the real risk is one layer further out: the adapter it runs declares a wire contract
  that was never checked against a provider. A schedule multiplies that. The correction
  matters because the earlier framing pointed a reviewer at work that is done and away
  from work that is not. Entry 5's check 3 is where the schedule is now reviewed, and
  the register states the unverified provider contract in full as **O-9**.

**Companion artefacts.** Each answers a different question, and none duplicates
another. Consult them directly rather than relying on the summaries above.

| Document | What it holds |
|----------|---------------|
| [`../security/DECISION_LOG.md`](../security/DECISION_LOG.md) | The reasoning behind every decision, the alternatives weighed and the risks accepted. The single source of truth for why |
| [`../security/TRACEABILITY_MATRIX.md`](../security/TRACEABILITY_MATRIX.md) | Each of the 20 findings mapped to the files that remediate it and the tests that verify it, in both directions |
| [`../security/RESIDUAL_RISK.md`](../security/RESIDUAL_RISK.md) | Both advisory registers — the seven in the runtime manifest and the one in the development manifest, eight in total and disjoint — each with its unreachable fix version and the measurement behind its compensating control. Also the eight open items above, stated in full and kept outside every advisory count |
| [`../security/CREDENTIAL_ROTATION.md`](../security/CREDENTIAL_ROTATION.md) | The ordered operational runbook for the exposed credentials |
