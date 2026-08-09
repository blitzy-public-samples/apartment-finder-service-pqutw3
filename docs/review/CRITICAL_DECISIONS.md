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
| 5 | Accept seven residual dependency advisories to hold the Python 3.9 pin | **Medium** | Ambiguity-resolving assumption | DevOps |

Entries 2 to 5 are reviewed against the change set as delivered. Entry 1 is reviewed
last, for the reason given in [Section 6](#6-review-sequencing-and-companion-artefacts).

---

## 1. Rotate the exposed credentials rather than only removing them from the working tree

- **Risk level:** High
- **Rule 3 category:** irreversible operation
- **Reviewer:** DevOps

### Decision and alternatives

The database credentials and the Google Cloud service-account key exposed by this
repository are treated as already compromised and are rotated, following the ordered
runbook at [`../security/CREDENTIAL_ROTATION.md`](../security/CREDENTIAL_ROTATION.md).
The alternative was to delete the values from the current tree and stop there.

The change set itself performs only the tree removal. Revocation and rotation are
operator actions, deferred to the runbook and sequenced last. Row 16.6 of the decision
log owns that reasoning.

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

Removal addresses only future exposure. Git history is permanent: each value above
remains in every commit that carried it, and every clone, fork, mirror, backup and
continuous-integration cache taken since carries that history. Only revocation and
rotation address the exposure that has already happened.

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

[`../security/CREDENTIAL_ROTATION.md`](../security/CREDENTIAL_ROTATION.md) is the
authoritative runbook and its Section 4 is the verification checklist; work from that
rather than from this summary. Record the outcome of every check, because an
unrecorded verification is indistinguishable from a skipped one.

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

`backend/app/db/models.py:7-17` declared `User` with only `id`, `email`,
`hashed_password`, `created_at` (`nullable=False`, at `:13`) and `last_login`, plus
two relationships. **There was no `role` column at all**, so no authorization decision
had anywhere to read a role from, and every protected route resolved through a
dependency that answered only whether the caller was authenticated.
`models.py:67-76` likewise declared `Subscription` with only `id`, `user_id`,
`start_date`, `end_date` and `status` — no plan, amount, currency or order-identifier
column, so no ownership check against a payment was possible either.

Separating the grant into its own revision is itself the audit control. One revision
carries one log record, one asserted post-condition and one downgrade, so a reviewer
can answer who was granted privilege, when, and by which statement, from a single
artefact. The role column now carries a server default of `registered` at
`models.py:19`, which is what allows the additive revision to land every pre-existing
account on the default role while granting nothing.

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
   administrator at all, and that its downgrade drops only the added columns.
5. Confirm the seed revision's downgrade demotes the seeded account back to
   `registered`.
6. Confirm the revision is idempotent by applying it twice and re-checking the
   administrator count.
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

## 5. Accept seven residual dependency advisories to hold the Python 3.9 pin

- **Risk level:** Medium
- **Rule 3 category:** ambiguity-resolving assumption
- **Reviewer:** DevOps

### Decision and alternatives

Seven dependency advisories are accepted as residual risk, each with a named
compensating control, rather than advancing the Python interpreter so that their fixes
become installable. The alternative was to advance the runtime.

**The ambiguity this resolved:** the instruction that the dependency audit report zero
advisories stood against the instruction never to advance the runtime. Row 1.9 of the
decision log owns the choice, and
[`../security/RESIDUAL_RISK.md`](../security/RESIDUAL_RISK.md) is the authoritative
register, carrying the measurement behind every compensating control.

### Rationale

The pin is load-bearing in five independent places, and the decisive one is code
rather than configuration. `backend/app/tasks/listing_updater.py:10` applies
`@asyncio.coroutine` to an `async def`; that decorator was removed in Python 3.11, so
the codebase itself would break on a newer interpreter. The pin is therefore a
property of the code and not merely of its configuration. The other four sites are
`infrastructure/docker/Dockerfile.backend:2`, `.github/workflows/ci.yml:19`,
`infrastructure/terraform/main.tf:99`, and `scripts/deploy.sh:24`. That last line is
cited for its retained runtime flag specifically: it is a single line that also carried
the `--allow-unauthenticated` flag this change removes, so it is not an untouched line.

Every accepted advisory's fix version lies above the highest release installable under
the pin, and each defect was proven unreachable in this codebase before it was
accepted. Five of the seven are against `starlette` 0.49.3, one against
`python-dotenv` 1.2.1, and one against `click` 8.1.8; the register names each
identifier with its unreachable fix version and the evidence behind its control.

The dependency position still improves substantially. Advisories fall from 19 across 7
packages to 7 across 3 — a 63% reduction — and static-analysis findings at Medium or
above fall from 1 to 0.

### Reviewer persona and exactly what to check

**DevOps.**

1. Confirm the dependency audit run against the manifest — not against the installed
   environment, which conflates the audit tool's own dependency tree with the
   application's — reports exactly the seven advisories the register names and nothing
   further.
2. Confirm each of the seven has a compensating control that is genuinely in place
   rather than a stated intention, checking each against the evidence recorded in the
   register.
3. Confirm both continuous-integration guards are wired, so that the acceptance cannot
   silently decay:
   - **Guard 1**, asserting the omitted `python-multipart` package stays absent. Its
     reintroduction would return six advisories and silently lapse the control
     recorded for PYSEC-2026-249.
   - **Guard 2**, the eight-pattern reachability guard over Python files under
     `backend/`. It reads zero today.
4. Confirm both guards fail the build rather than merely report, by inspecting how each
   step's exit status is handled.
5. Confirm all five pin sites still carry the pinned runtime, including
   `scripts/deploy.sh:24`, where the runtime flag is retained while
   `--allow-unauthenticated` is removed.
6. Confirm the register's reproduction instructions still yield the same seven
   advisories on the pinned interpreter, so that the acceptance rests on a measurement
   a reviewer can repeat rather than on an assertion.

---

## 6. Review sequencing and companion artefacts

**Review sequencing.** Review entries 2 to 5 against the change set as delivered.
Entry 1 is reviewed last, because the operation it covers is performed last: credential
rotation cannot be rolled back, so it is executed only after every other change has
been deployed and verified, in its own change window. Reviewing it any earlier reviews
an intention rather than an action.

**The single break in compatibility.** Entry 3 is the only intentional breaking change
in this work. Everything else preserves existing behaviour by construction — the login
response shape, every route path, every router prefix, the public reachability of the
listings read endpoint, and the verifiability of every stored password hash.

**Findings outside the stated scope.** Ten security-relevant issues were discovered
outside the scope of this work. All ten are flagged and awaiting confirmation; none is
fixed or resolved here, and none is a review item for this document. Row 34.6.3 of the
decision log enumerates them.

**Companion artefacts.** Each answers a different question, and none duplicates
another. Consult them directly rather than relying on the summaries above.

| Document | What it holds |
|----------|---------------|
| [`../security/DECISION_LOG.md`](../security/DECISION_LOG.md) | The reasoning behind every decision, the alternatives weighed and the risks accepted. The single source of truth for why |
| [`../security/TRACEABILITY_MATRIX.md`](../security/TRACEABILITY_MATRIX.md) | Each of the 20 findings mapped to the files that remediate it and the tests that verify it, in both directions |
| [`../security/RESIDUAL_RISK.md`](../security/RESIDUAL_RISK.md) | The seven accepted advisories, their unreachable fix versions, and the measurement behind each compensating control |
| [`../security/CREDENTIAL_ROTATION.md`](../security/CREDENTIAL_ROTATION.md) | The ordered operational runbook for the exposed credentials |
