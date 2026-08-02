# Security Remediation Traceability Matrix

This matrix maps each of the twelve security findings to the files that carry its control, and each
file back to the findings it closes. A reviewer can therefore confirm coverage without reconstructing
intent from a diff.

Findings are identified `SEC-01` through `SEC-12`, the numbering supplied with the brief. Severity
ratings are the reporter's. Weakness classifications are analysis rather than database lookups: none
of the twelve is a published vulnerability in this codebase, so none carries a CVE identifier.

Paths are relative to the repository root. Where a sentence describes a defect, its line reference
locates the code as it stood before the change, and a few of those lines have since moved.

**What lives elsewhere.** [`decision-log.md`](decision-log.md) is the single source of truth for
**why** each choice was made, and it holds the alternatives weighed and the risks accepted.
[`SECURITY.md`](../../SECURITY.md) carries operational secret handling, the verification commands, the
deferred follow-ons and the residual-risk register. This file records **what closes what, and where**.
Neither companion document is restated here.

## The scope judgment

Rule 1 conditions this artifact on a class of work: "For migrations or refactors, include a
bidirectional traceability matrix mapping source constructs to target implementations — 100%
coverage, no gaps." A security remediation is neither, in the ordinary sense. Two parts of it qualify
on any reasonable reading: SEC-06 migrates the session token from browser storage to an `HttpOnly`
cookie, and `backend/requirements.txt` migrates an implicit, unpinned dependency set into an explicit,
pinned one. Rather than argue the boundary, the matrix covers all twelve findings in both directions.
The broader reading costs a page and makes the coverage claim checkable instead of asserted.

## How to read it

- **Section 1** runs finding to control to file. Every mechanism is stated once, there.
- **Section 2** runs file to control to finding, grouped by directory. Cells name the control and
  point back to section 1 rather than repeating it.
- **Section 3** reconciles the two directions, and states where delivery departed from the plan.
- **Section 4** carries the measured evidence: what each gate read before the work and after it.
- **Section 5** lists the design intent in the sibling specifications that this work does and does
  not deliver.

---

## 1. Direction A — finding to control to file

Thirteen rows: the twelve findings, plus the dependency-integrity prerequisite that had to be closed
before any of them could be tested. Four rows are labelled **Partial**, with the remaining gap named;
[`SECURITY.md`](../../SECURITY.md) section 3.2 carries the operator-facing detail on all four.

| Finding | Weakness and severity | Control that closes it | Files carrying the control |
| --- | --- | --- | --- |
| **SEC-01** | Hardcoded credentials in a tracked file. CWE-798, CWE-540. A07:2021, secondary A05:2021. Critical | Environment indirection with no inline default replaces the literal at `docker-compose.yml:30`, so a missing value fails loudly instead of falling back. The Compose variable name at `:31` changes from `JWT_SECRET` to `SECRET_KEY`, the name the backend settings class actually reads. New exclusion and template files keep a generated secret file uncommittable, and the development script generates credentials instead of emitting them | `.gitignore`, `.env.example`, `infrastructure/docker/docker-compose.yml`, `scripts/setup_dev_environment.sh`, `.github/workflows/ci.yml` |
| **SEC-02** | Broken authentication through identity mismatch. CWE-287, CWE-863. A01:2021. High | The subject claim is minted as `str(user.id)` and coerced back with `int()` inside a guard that answers 401, so the claim and the queried column share a type. The bare 404 at `security.py:49-50` becomes a 401 carrying `WWW-Authenticate: Bearer`, an `iat` claim joins the existing `exp`, and the outbound user model retypes `id` from `str` to `int` and drops its password-hash field | `backend/app/core/security.py`, `backend/app/api/endpoints/auth.py`, `backend/app/schema/user.py`, `backend/tests/security/test_auth_identity.py` |
| **SEC-03** | Permissive cross-origin policy with credentials. CWE-942, CWE-346. A05:2021. High | `ALLOWED_ORIGINS` becomes a required list whose validator rejects an empty list, `"*"`, the literal `"null"` and any entry that is not a full origin. Matching is exact string equality, with no reflection and no regular expression, and the two middleware wildcards give way to explicit method and header lists. A misconfigured allow-list stops startup | `backend/app/core/config.py`, `backend/app/main.py`, `.env.example`, `backend/tests/security/test_cors_policy.py` |
| **SEC-04** | Weak password requirements. CWE-521. A07:2021. Medium | A validator on the new `UserCreate` model mirrors the client character set at `validators.ts:18-32`, twelve characters with an upper, a lower, a digit and a special character, and adds a hard maximum at the 72-byte bcrypt ceiling. The maximum is mandatory rather than defensive: at the pinned `bcrypt==4.3.0` a 100-character password is accepted silently, so the library supplies no protection | `backend/app/schema/user.py`, `backend/app/api/endpoints/auth.py`, `backend/tests/security/test_password_policy.py` |
| **SEC-05** | Improper input validation and mass assignment. CWE-20, CWE-915. A03:2021, secondary A04:2021. High | `UserCreate`, `UserLogin`, `FilterCreate` and `ListingCreate` arrive alongside a new `subscription.py` module, and every create model sets `extra = "forbid"` so an unknown key is rejected rather than absorbed. That single setting is the mass-assignment control for `listings.py:23`, which expands the request body straight into a mapped constructor | `backend/app/schema/user.py`, `backend/app/schema/filter.py`, `backend/app/schema/listing.py`, `backend/app/schema/subscription.py`, `backend/tests/security/test_input_validation.py` |
| **SEC-06** | Session token in browser-accessible storage. CWE-522, CWE-1004. A07:2021. Medium | Both auth routes set an `HttpOnly`, `Secure`, `SameSite=Strict` cookie while leaving the JSON body untouched, and the guard reads that cookie before the bearer header, so non-browser clients still work. `POST /auth/logout` clears it, because script cannot delete a cookie it cannot read. The frontend drops browser storage, corrects its request path to `/auth/login`, exports `API_BASE_URL` and sends credentials; axios is pinned exactly and the cross-site-token option is deliberately left unset | `backend/app/core/security.py`, `backend/app/api/endpoints/auth.py`, `backend/app/core/config.py`, `frontend/src/services/auth.ts`, `frontend/src/services/api.ts`, `frontend/package.json`, `backend/tests/security/test_token_storage.py` |
| **SEC-07** | Unrestricted authentication attempts. CWE-307. A07:2021. Medium. **Partial** | A limiter with in-memory storage applies five attempts per fifteen minutes to `POST /auth/login`, layered with an in-process counter keyed by normalized lowercase email so a distributed attempt on one account is also bounded. Throttled attempts are logged rather than silently dropped. **Gap**: the state is per-worker and lost on restart, so lockout is neither durable nor multi-replica-safe | `backend/app/main.py`, `backend/app/api/endpoints/auth.py`, `backend/app/core/config.py`, `backend/tests/security/test_login_throttle.py` |
| **SEC-08** | Information exposure through an error message. CWE-209, CWE-497. A05:2021. Medium | Four global handlers replace the placeholder comment at `main.py:35`, sharing one response envelope and a correlation identifier while full diagnostics go to the server log. Uniformity is the requirement rather than the style, which is why the SEC-02 normalisation of the 404 into a 401 belongs here too: a differential response is an account-state oracle | `backend/app/main.py`, `backend/app/core/security.py`, `backend/tests/security/test_error_handling.py` |
| **SEC-09** | Insecure default initialization of a resource. CWE-1188, CWE-798. A05:2021. High | `PAYPAL_MODE` is restricted to `sandbox` or `live`, and the service reads it from the settings class in place of the hardcoded literal and its manual-edit comment, which stood at `paypal_service.py:11`. A pipeline step asserts that no client-secret pattern appears under `frontend/`; the property already held, so the step converts an accident into an invariant | `backend/app/core/config.py`, `backend/app/services/paypal_service.py`, `backend/app/api/endpoints/subscriptions.py`, `.github/workflows/ci.yml`, `backend/tests/security/test_config_guards.py` |
| **SEC-10** | Cleartext transmission to the database. CWE-319. A02:2021. High. **Partial** | The Cloud SQL instance gains `ip_configuration { ssl_mode = "ENCRYPTED_ONLY" }`, and the engine passes an environment-driven `sslmode` through `connect_args` for PostgreSQL URLs only, because SQLite raises `TypeError` on that argument. Both ends are needed: the Auth Proxy encrypts its own tunnel while the instance keeps accepting unencrypted direct connections until the mode is set. The deprecated `require_ssl` argument is not used. **Gap**: `require` encrypts but performs no server-identity check | `infrastructure/terraform/main.tf`, `infrastructure/terraform/variables.tf`, `backend/app/core/config.py`, `backend/app/db/database.py`, `infrastructure/docker/docker-compose.yml`, `.env.example`, `backend/tests/security/test_config_guards.py` |
| **SEC-11** | Execution with unnecessary privileges. CWE-250, CWE-269. A01:2021. Medium. **Partial** | The single all-privileges account splits into an owner role used for schema work and an application role holding only connect, schema usage and table data rights, with `CREATE` revoked from `PUBLIC`. Terraform declares a `google_sql_user` whose password comes from a variable rather than a literal. **Gap**: nothing here delivers row-level security | `scripts/setup_dev_environment.sh`, `infrastructure/terraform/main.tf`, `infrastructure/terraform/variables.tf`, `.gitignore` |
| **SEC-12** | Insufficiently protected credentials in custody. CWE-522. A05:2021. Medium. **Partial** | Exclusion rules and a value-free template keep secrets out of version control, and matching build-context rules keep them out of every container image. `SECRET_KEY` gains a `min_length=32` floor grounded in RFC 7518 section 3.2, the three settings that raised `AttributeError` are declared, and a pipeline secret scan enforces the discipline. **Gap**: no managed secret store, and deployment still authenticates with a long-lived credential | `.gitignore`, `.env.example`, `SECURITY.md`, `backend/app/core/config.py`, `.github/workflows/ci.yml`, `backend/tests/security/test_config_guards.py`, and the three build-context files in section 3.4 |
| **Prerequisite** | No dependency manifest, so the dependency surface had never been enumerated. CWE-1104. A06:2021 | `backend/requirements.txt` pins nineteen packages exactly, fourteen runtime and five for test and audit tooling. Two pins are load-bearing beyond version hygiene: `bcrypt==4.3.0` prevents a passlib capability probe that would break every password hash, and omitting a multipart parser keeps six advisories that cannot be patched on this runtime out of the closure | `backend/requirements.txt`, `.github/workflows/ci.yml` |

---

## 2. Direction B — file to control to finding

Thirty-nine rows, one per file in the planned change set, grouped by directory. **Mode** is `CREATE`,
`UPDATE` or `REFERENCE`, where a reference file is read as an authority and deliberately left
unchanged. Controls are named, not re-explained; section 1 holds the mechanism.

### 2.1 Repository root

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `.gitignore` | CREATE | Excludes the environment file, the secrets directory, certificates, keys and credential JSON, plus Terraform state and variable files that would carry a database password in cleartext | SEC-01, SEC-11, SEC-12 |
| `.env.example` | CREATE | Documents every required variable by name, shape and purpose, with placeholder values only, including the JSON-array form the origin list expects | SEC-01, SEC-03, SEC-10, SEC-12 |
| `SECURITY.md` | CREATE | Operator-facing custody procedure, verification commands, residual-risk register and the deferred follow-ons | SEC-12 |

### 2.2 Backend application

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `backend/requirements.txt` | CREATE | Nineteen exact pins, including the availability-critical `bcrypt==4.3.0`; unblocks `Dockerfile.backend` and the pipeline install step, both of which already referenced this file | Prerequisite (CWE-1104) |
| `backend/app/core/config.py` | UPDATE | Validated security settings: the required origin allow-list, the payment-mode domain, the transport mode, the cookie flag, the limiter thresholds, the signing-key floor and the three settings that previously raised `AttributeError` | SEC-03, SEC-06, SEC-07, SEC-09, SEC-10, SEC-12 |
| `backend/app/main.py` | UPDATE | Explicit method and header lists on the cross-origin middleware, the limiter registration and its exceeded handler, and the four global exception handlers. Also corrects the import source for `Base`, which is boot-blocker layer four | SEC-03, SEC-07, SEC-08 |
| `backend/app/core/security.py` | UPDATE | Integer coercion of the subject inside a 401 guard, the uniform 401 with `WWW-Authenticate: Bearer`, the `iat` claim, and the cookie-before-header read | SEC-02, SEC-06, SEC-08 |
| `backend/app/api/endpoints/auth.py` | UPDATE | Mints the subject as the user identifier, hands the password to a validating schema before hashing, sets and clears the session cookie, adds `POST /auth/logout`, and applies the login limit. Also supplies the non-null `created_at` without which registration always failed | SEC-02, SEC-04, SEC-06, SEC-07 |
| `backend/app/api/endpoints/listings.py` | UPDATE | One line: the model import at `:7` extends to include `User`, resolving the annotation at `:18`. Boot-blocker layer two, carrying no control of its own | Enabling repair |
| `backend/app/schema/user.py` | UPDATE | Strict create and login models, the password policy with its byte ceiling, the integer identifier, and removal of the password-hash field from the outbound model | SEC-02, SEC-04, SEC-05 |
| `backend/app/schema/filter.py` | UPDATE | Strict allow-list of writable filter fields, applied to the nested criteria as well | SEC-05 |
| `backend/app/schema/listing.py` | UPDATE | Strict allow-list of writable listing fields, the control for the mass-assignment site | SEC-05 |
| `backend/app/schema/subscription.py` | CREATE | Supplies the create and response models the subscription endpoint already imported from a module that did not exist. Boot-blocker layer one | SEC-05 |
| `backend/app/db/database.py` | UPDATE | Passes the transport mode through `connect_args`, conditionally and only for PostgreSQL URLs | SEC-10 |
| `backend/app/services/paypal_service.py` | UPDATE | Reads the payment environment from the validated setting. Also adds the missing typing import for both annotation sites and the async wrapper the subscription endpoint calls, clearing boot-blocker layers two and three | SEC-09 |
| `backend/app/db/models.py` | REFERENCE | The authority for column types and nullability, and the reason no schema change is proposed: with no migration tooling, a new column or default never reaches an existing table. Verified byte-identical | Authority for SEC-02, SEC-05 |
| `backend/app/api/endpoints/filters.py` | REFERENCE | The reference pattern for a declared `response_model`, the one write endpoint that already had one. Verified byte-identical; an earlier edit here was withdrawn, see section 3.4 | Authority for SEC-05 |
| `backend/app/api/endpoints/subscriptions.py` | REFERENCE | The authority whose import at `:7` and its call site dictated the wrapper signature added to the payment service. Verified byte-identical; an earlier edit here was withdrawn, see section 3.4 | Authority for SEC-09 |

### 2.3 Backend tests

Every file here is a vulnerability regression test: each asserts that one specific weakness is no
longer exploitable.

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `backend/tests/conftest.py` | CREATE | The harness the other eight depend on: dual import paths, environment injection before the application is imported, a real SQLite session override, and an HTTPS base URL so a `Secure` cookie persists under test | Verification for SEC-02 to SEC-12 |
| `backend/tests/security/test_auth_identity.py` | CREATE | Asserts the subject round-trip, that an email subject is refused with 401 rather than 500, that an unresolvable subject answers 401 rather than 404, and that `iat` is present | SEC-02 |
| `backend/tests/security/test_cors_policy.py` | CREATE | Asserts an allow-listed origin is echoed with credentials, a foreign origin receives no allow-origin header, and an unsafe configuration prevents startup | SEC-03 |
| `backend/tests/security/test_password_policy.py` | CREATE | Asserts rejection below twelve characters, for each missing character class, and above the byte ceiling, plus acceptance of a compliant password | SEC-04 |
| `backend/tests/security/test_input_validation.py` | CREATE | Asserts an unknown field is rejected with 422, which is the mass-assignment assertion, and that malformed, missing and wrongly typed fields never produce a 500 | SEC-05 |
| `backend/tests/security/test_token_storage.py` | CREATE | Asserts the three cookie attributes, that the JSON body keeps its exact key set, that a cookie-only request authenticates, that the bearer fallback still works, and that logout ends the session | SEC-06 |
| `backend/tests/security/test_login_throttle.py` | CREATE | Asserts that the sixth consecutive failed login returns 429, that the throttled body uses the uniform envelope, and that throttled attempts are logged | SEC-07 |
| `backend/tests/security/test_error_handling.py` | CREATE | Asserts a sanitized 500 carrying no traceback or internal detail, a 422 carrying field names only, envelope uniformity across handlers, and a correlation identifier in both response and log | SEC-08 |
| `backend/tests/security/test_config_guards.py` | CREATE | Asserts the payment-mode domain, the signing-key length floor, and that the transport argument is applied for PostgreSQL and withheld for SQLite | SEC-09, SEC-10, SEC-12 |
| `backend/tests/test_api.py` | REFERENCE | The authority for existing harness conventions. Verified byte-identical, and it still fails collection with the same import error as before, so the new harness did not change its outcome | Authority for the harness |

### 2.4 Frontend

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `frontend/src/services/auth.ts` | UPDATE | Removes all browser token storage, corrects the request path to `/auth/login`, and delegates logout to the server route that can clear an `HttpOnly` cookie | SEC-06 |
| `frontend/src/services/api.ts` | UPDATE | Two lines: exports the base URL that the auth module already imported, and sends credentials so the browser transmits the session cookie. The cross-site-token option is deliberately left unset | SEC-06 |
| `frontend/package.json` | UPDATE | One line: the axios caret range becomes an exact pin, removing a declared floor that sat inside the CVE-2023-45857 range now that credentialed mode is enabled | SEC-06 prerequisite |
| `frontend/src/utils/validators.ts` | REFERENCE | The authority for the password character set at `:18-32`, mirrored by the server validator so the two cannot drift. Verified byte-identical | Authority for SEC-04 |

### 2.5 Infrastructure and provisioning

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `infrastructure/docker/docker-compose.yml` | UPDATE | Environment indirection with no inline default, the corrected secret variable name, and the documented local transport exception for the Auth Proxy topology | SEC-01, SEC-10 |
| `infrastructure/terraform/main.tf` | UPDATE | The encryption-only IP configuration on the Cloud SQL instance, and the least-privilege database user declared as infrastructure | SEC-10, SEC-11 |
| `infrastructure/terraform/variables.tf` | UPDATE | The transport, network and database credential variables the new configuration requires, declared with no default for the sensitive one | SEC-10, SEC-11 |
| `scripts/setup_dev_environment.sh` | UPDATE | Generated rather than literal credentials, and the owner plus application role split that replaces the unrestricted grant. Three of the four original credential-scan hits were in this file | SEC-01, SEC-11, SEC-12 |

### 2.6 Pipeline

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | UPDATE | The four enforcement gates and the authoritative definition of each scan pattern: the dependency audit with its justified suppressions and staleness check, the credential scan, the frontend client-secret guard, and the browser-storage guard | SEC-01, SEC-06, SEC-09, SEC-12, Prerequisite |

### 2.7 Security documentation

Both files here trace to **Rule 1 (Explainability)** rather than to a finding. Neither appears in any
of the twelve, and their presence is a rule obligation rather than a coverage gap.

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `documentation/security/decision-log.md` | CREATE | The four-column decision table: what was decided, what alternatives existed, why the choice won, and what risk it leaves. The single source of truth for rationale | Rule 1, not a finding |
| `documentation/security/traceability-matrix.md` | CREATE | This file. The bidirectional finding-to-file map that makes the coverage claim checkable | Rule 1, not a finding |

---

## 3. Coverage reconciliation

### 3.1 The arithmetic

| Mode | Count | Where they sit |
| --- | --- | --- |
| CREATE | 16 | 3 at the repository root, 11 under `backend/`, 2 under `documentation/security/` |
| UPDATE | 18 | 10 under `backend/`, 3 under `frontend/`, 3 under `infrastructure/`, 1 under `scripts/`, 1 under `.github/` |
| REFERENCE | 5 | 4 under `backend/`, 1 under `frontend/` |
| DELETE | 0 | See section 3.2 |
| **Total** | **39** | Section 2 carries one row for each |

Both directions are complete. Every one of `SEC-01` through `SEC-12` has at least one file in section
1, and every file in section 2 traces to a finding, to the dependency prerequisite, to an enabling
repair, or to Rule 1. Section 3.4 records that nothing else the branch touches sits outside those
thirty-nine paths.

### 3.2 Zero deletions, stated deliberately

No file was deleted, and the zero is a finding rather than an empty cell. No file in this repository
introduces a weakness that removal would fix: every one of the twelve is closed by correcting, adding
or configuring. A reviewer checking completeness should be able to see that the absence of a deletion
was decided rather than overlooked.

One removal did happen, one level down. A multipart parser was left out of the new manifest rather
than pinned, which closed six advisories that no version available on this runtime could close. That
is a dependency decision, not a file deletion.

### 3.3 Files whose absence is the point

Five reference files are read as authorities and deliberately left unchanged. Listing them is what
shows a reviewer that `backend/app/db/models.py` was consulted and then left alone, rather than
missed. The model file matters most: no column and no default was added, because with no migration
tooling neither would ever reach an existing table.

### 3.4 Plan versus delivery

**No path departs from the planned classification.** Delivery and plan agree exactly: 16 created, 18
updated, 5 references left byte-identical, no deletions, across the same 39 paths section 3.1
enumerates. Counting delivery rather than plan changes none of those five figures, so this subsection
records a convergence rather than a difference.

Three earlier departures were withdrawn, and each withdrawal is a decision in its own right rather
than a quiet tidy-up.

| Path | Planned | Delivered | What changed, and where the reasoning sits |
| --- | --- | --- | --- |
| `backend/app/api/endpoints/filters.py` | REFERENCE | REFERENCE, byte-identical | The endpoint edit was reverted: a frozen reference file is not the place to repair a create path that cannot persist for schema reasons. The defect it addressed is recorded instead, with the sanitized fault the route now answers. Log section 9, `DL-32` |
| `backend/app/api/endpoints/subscriptions.py` | REFERENCE | REFERENCE, byte-identical | The caller edit went with the payment verifier that required it. With the service back at its documented three-callable surface, nothing asks the caller to name a plan. Log section 19, `DL-201` |
| `.dockerignore`, `backend/.dockerignore`, `frontend/.dockerignore` | not planned | not delivered | Three unplanned files were removed. Build-context filtering is real but belongs to no finding in this pass, and the file map is the scope statement. Log section 15.9, `DL-127` through `DL-129` |

The planned classification in sections 2 and 3.1 is the authoritative scope statement, and the tree
now matches it with nothing left over.

### 3.5 What this matrix deliberately omits

Weaknesses found during the work but not fixed carry no file, so they have no row here. They are
recorded instead in [`decision-log.md`](decision-log.md) section 34, with the operator-facing view in
[`SECURITY.md`](../../SECURITY.md) section 3.4. Their absence from this matrix is deliberate and is
not a coverage gap.

The three documents also give three different counts for that list, and the reason is worth one
sentence. One observation on the original list was closed rather than deferred. The outbound user
model no longer declares a password-hash field, removed alongside the SEC-02 identity correction
because the same model was already being edited. It therefore appears in this matrix, under
`backend/app/schema/user.py`, rather than on the deferred list.

---

## 4. Verification evidence

### 4.1 The three repository scans

These are the effectiveness metrics, made executable. All three run in
[`ci.yml`](../../.github/workflows/ci.yml), which is the authoritative definition of each pattern.

| Gate | What it checks | Before | Now | Character |
| --- | --- | --- | --- | --- |
| One | Credential patterns across tracked repository content | 4 | 0 | Remediation |
| Two | Client-secret patterns anywhere under `frontend/` | 0 | 0 | Regression prevention |
| Three | Browser token storage anywhere under `frontend/src/` | 3 | 0 | Remediation |

Gate one flags the well-known default PostgreSQL credential pair, an inline SQL password literal, an
assigned signing-key value, and any connection URL carrying an embedded password. Its four hits sat in
the Compose environment block and in three lines of the development setup script. That last count
settles a scope question by measurement. Three of the four sat in a file the twelve findings never
name, so `scripts/setup_dev_environment.sh` had to be in scope or the metric could not reach zero.

**This document describes gate one rather than reproducing it.** A pattern built from
credential-shaped strings matches the text that declares it, so any file quoting the pattern becomes a
hit and the required count of zero turns unreachable. Measured on a tree holding no credential at all,
quoting the pattern was enough to fail the gate. Read the workflow for the exact expression;
[`SECURITY.md`](../../SECURITY.md) section 2.6 covers all three scans and
[`decision-log.md`](decision-log.md) section 36 carries the reasoning.

Gate three's three hits were the write, the remove and the read of the stored token, all in the
frontend authentication service at `auth.ts:11`, `:21` and `:25`, with the key declared at `:5`. Gate
two never had a hit, so its pipeline step prevents a regression rather than closing one.

### 4.2 Test and style baselines

A green pipeline is not on offer, and claiming one would be false. The numbers below are measured, so
that "no new failures" means something.

| Measure | Before | Now |
| --- | --- | --- |
| Tests collected under `backend/` | 0, with 3 collection errors | 513 collected, with the same 3 collection errors |
| `tests/security` result | did not exist | 513 passed |
| Style findings under `backend/` | 129 | 111 |
| Undefined names | 4 | 1 |

The three pre-existing test modules still fail to import, for reasons that predate this work and are
outside its scope. The four undefined names were `listings.py:18`, `subscriptions.py:54` and two
annotation sites in `paypal_service.py`; three are gone, and the one that remains is the out-of-scope
missing datetime import in the subscription endpoint. Creating the manifest is what allowed the
pipeline to reach these steps at all, so they are running for the first time rather than newly
failing.

### 4.3 Infrastructure validation

Plan review does not run today, and it has **two** independent pre-existing blockers rather than one.
`outputs.tf` references nine resource addresses of which only two are declared in `main.tf`; the seven
absent ones are three storage buckets, two messaging topics and two functions. Separately, `main.tf:34`
reads `var.gke_num_nodes`, which `variables.tf` declares nowhere.

Both blockers predate this work and neither follows from it. Neither breaks an automated gate either,
because no workflow in this repository invokes Terraform at all. Repairing them is unrelated cleanup;
[`SECURITY.md`](../../SECURITY.md) section 2.7 carries the workaround for validating the changed
resource in the meantime.

---

## 5. Design intent in the sibling specifications

The three documents under `documentation/` are read as corroborating evidence and are not modified.
Reconciling them with the delivered state is documentation work outside this scope.

### 5.1 Corroborated there

Several controls are documented design intent rather than inventions of this pass, which is worth
knowing when reviewing a threshold.

| Control | Where the specifications say so |
| --- | --- |
| SEC-04's twelve-character minimum and its four character classes | `Technical Specifications.md:596-598` |
| SEC-07's five-attempt, fifteen-minute threshold | `Technical Specifications.md:607` |
| Token-based sessions with a bounded lifetime | `Technical Specifications.md:609-612` |
| SEC-10's encrypted transport | `Technical Specifications.md:655-657`, `SRS:513` |
| SEC-12's managed secret store | `SRS:908-913`, a Secret Manager code example |
| Encryption at rest and key management | `Technical Specifications.md:651-653`, `SRS:514`, `SRS:755-758` |
| Compliance context for GDPR and CCPA | `Technical Specifications.md:670`, `SRS:517-518` |
| Application-layer role-based access control | `Technical Specifications.md:616-618`, `SRS:393`, `SRS:509`, `Software Project Proposal.md:465` |

Two claims are worth stating precisely, because the obvious citation for each does not exist.

- **Row-level security appears nowhere in the three specifications.** A search across
  `documentation/` returns no match. The SEC-11 gap therefore rests on the analysis in the brief and
  on the verifiable absence of any row-level policy in the repository, not on a document that names
  it. The role-based access control cited above is an application-layer control and a different
  thing.
- **No specification states that the client cannot complete an authenticated request.** The evidence
  is first-hand instead, and stronger for it. Five layers of import-time failure stood between the
  repository and a running process. The guard at `security.py:48` also compared a subject typed `str`
  at `:35` against the integer primary key declared at `models.py:10`.

### 5.2 Named there, not delivered here

Each gap below is either on the exclusion list supplied with the brief or is one of the four labelled
partial remediations. [`decision-log.md`](decision-log.md) section 35 records each one;
[`SECURITY.md`](../../SECURITY.md) section 4 lists the follow-ons in priority order.

| Design intent | Status here |
| --- | --- |
| Optional time-based one-time-password authentication, at `Technical Specifications.md:601-603` and `SRS:506` | Excluded by the brief |
| OAuth 2.0 authentication, at `SRS:505` | Excluded by the brief |
| A managed secret store, at `SRS:908-913` | Deferred; SEC-12 delivers custody discipline instead |
| Encryption at rest under a managed key service, at `Technical Specifications.md:651-653` | Out of scope; no finding covers it |
| Certificate-verifying database transport | Deferred; SEC-10 delivers encryption without identity verification |
| Row-level security | Deferred; SEC-11 delivers role separation only |

The specifications also disagree with themselves on one point, noted once and left alone: `SRS:891`
requires TLS 1.2 or higher for payment transactions, while `SRS:513` and
`Technical Specifications.md:656` require 1.3 or higher. Reconciling the two is documentation work
outside this scope.

Two pre-existing frontend defects are named here so neither is read as new. The navigation component
at `frontend/src/components/NavBar.tsx:3` imports a `useAuth` hook from the authentication service,
which exports only `login` and `logout`. The specifications sketch that hook at
`Technical Specifications.md:628`, importing it from a `hooks` directory the repository does not
contain. Neither the component nor the hook is in scope, and the acceptance criterion is that no
**new** failure appears.

The client-side password rule has the mirror-image problem, and it is why SEC-04 matters more than the
finding text suggests. Verified first-hand: `isValidPassword` occupies exactly one line in the whole
repository, its own declaration at `validators.ts:18`, and no registration component exists anywhere
under `frontend/src/`, although `SRS:809` calls for login and registration forms. The policy was
therefore enforced in **zero** places before SEC-04, not one.
