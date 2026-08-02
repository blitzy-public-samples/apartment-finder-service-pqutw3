# Security

This document records what the security pass on `apartment-finder-service` delivered, what it
deliberately left undone, and how to check both. It covers four things: how secrets are handled,
which commands verify the work, which risks remain, and which follow-ons are deferred.

Twelve findings were in scope, identified as `SEC-01` through `SEC-12`. None of the twelve is a
published vulnerability in this codebase, so none carries a CVE identifier. Severity ratings came
from the reporter. Weakness classifications and scoring vectors are analysis, not database
lookups. Third-party advisories are a separate matter and are cited below by their real
identifiers.

Two companion documents carry information this file does not duplicate:

- [`documentation/security/decision-log.md`](documentation/security/decision-log.md)
  is **the single source of truth for why** every choice was made. It carries the alternatives
  weighed and the risks accepted. Where a statement below needs defending, the log holds the
  reasoning, and this document does not repeat it.
- [`documentation/security/traceability-matrix.md`](documentation/security/traceability-matrix.md)
  maps findings to files in both directions at full coverage.

One piece of context explains several numbers in this document. Before this work, the application
could not start: five layers of import-time failure stood between the repository and a running
process, and each layer hid the next. Ten of the twelve findings were therefore unverifiable. That
is why the test baseline below is zero collected tests rather than a passing suite.

---

## 1. Secret handling and custody

### 1.1 Actions required outside the codebase

No commit performs any of these. They are operational, and they come in this order.

**Rotate every credential that was ever real.** Removing a value from a file does not un-disclose
it. Rotate the database password, the signing key, and the payment client secret. The credential
scan in section 2.6 proves that tracked content is clean today; it proves nothing about history.

The history finding is narrow. The credential literal appears in exactly one commit, the initial
add, and its value was the well-known PostgreSQL default rather than production material. No
history-rewriting tool was run and none is needed. Rotate anyway if any of these values was ever
used against a real system.

**Generate a new signing key of at least 32 bytes.** The application refuses to start below that
length. RFC 7518 section 3.2 requires HMAC-SHA256 keys of at least 256 bits, and
`backend/app/core/config.py` enforces the floor per algorithm: 32 UTF-8 bytes for HS256, 48 for
HS384, 64 for HS512. A useful side effect is that the floor blocks the twenty-character
placeholder the old setup script wrote from ever reaching a running system.

**Provision seven environment variables before the new build starts.** Four are new security
settings: the origin allow-list, the payment environment, the database SSL mode, and the cookie
Secure attribute. Three are settings the code already read but never declared: the Zillow endpoint
URL, the SendGrid API key, and the sender address. Without those three, the mail and Zillow
ingestion modules fail on first use. Two login-throttle thresholds are also new, but both carry
working defaults and need no action.

[`.env.example`](.env.example) is authoritative for every variable name, shape, and purpose. It
documents the JSON-array form the origin allow-list requires, the per-algorithm key floor, and the
one local-development exception for the database SSL mode.

**Restrict the secret file's permissions** to the owning service account, and confirm the ignore
rules exclude it before the first commit that could pick it up.

### 1.2 What the codebase contributes

[`.env.example`](.env.example) documents every variable by name, shape, and purpose, and contains
no value.

[`.gitignore`](.gitignore) prevents recurrence, which is the control that separates remediation
from cleanup. It excludes five secret-bearing patterns: `.env`, `secrets/`, `*.pem`, `*.key`, and
`*credentials*.json`. It also excludes Terraform state and variable files.

Those Terraform exclusions no longer rest on the state file holding the database password. The
shipped declaration passes the value through `password_wo` from an `ephemeral` variable, so it
reaches neither state nor a plan file. They stay excluded for two reasons that still hold: a
variable file is the conventional home for the value an operator supplies, and state records other
resource attributes worth keeping out of version control.

The `secrets/` entry matters more than it looks. The Compose stack mounts `./secrets` into the
database proxy container and reads a Google service-account credential file from it. Nothing
previously stopped that file from being committed.

The settings class rejects weak or missing security values while it loads, so a misconfiguration
surfaces as a failed boot rather than a silent weakening. Eleven variables are required with no
default.

Four settings carry an explicit domain. The origin allow-list refuses an empty list, the wildcard,
the literal `null`, and any entry that is not an exact browser-serialized origin. The payment
environment accepts only `sandbox` or `live`. The database SSL mode accepts only a value the driver
understands. The token algorithm accepts only the HMAC family.

### 1.3 What SEC-12 does not deliver

SEC-12 is a partial remediation. It delivers custody discipline, not a secret store.

- No managed secret store is provisioned, and no key-management service is configured.
- The deployment pipeline still authenticates with a long-lived service-account key rather than
  federated identity. `.github/workflows/cd.yml` passes that key to the Cloud SDK setup step and
  exports it as the default credential. Migrating to federated identity needs provider-side
  configuration that cannot be created or validated from this repository, so it is recommended in
  section 4 rather than implemented.

---

## 2. Verification commands

Every command below was executed against this repository or its resolved dependency stack. The
expected results are measured values, not predictions. Two commands are expected to fail, and
those two say so.

### 2.1 Environment preparation

Use the runtime the repository documents in four places, not the newest available. A dedicated
virtual environment is required; do not use the system interpreter even when its version would
satisfy the constraint.

```bash
python3.9 -m venv .venv
. .venv/bin/activate
cd backend && pip install -r requirements.txt
```

Expected: every pin resolves with no conflict. Verified on Python 3.9.25. The manifest pins
nineteen packages directly, fourteen for the runtime and five for test and audit tooling. The
runtime closure resolves to roughly forty packages. The rest arrive transitively, pinned by the
resolution rather than by hand, which is the right granularity without a lock file.

### 2.2 Security regression tests

The primary gate for eleven of the twelve findings.

```bash
cd backend && python -m pytest tests/security -q
```

Expected: all tests pass. The suite covers the identity claim, the origin allow-list, the password
policy, request validation, cookie attributes, login throttling, the error boundary, and the
configuration guards.

### 2.3 Full suite with coverage

This matches the pipeline invocation.

```bash
cd backend && python -m pytest --cov=./ --cov-report=xml
```

Expected: the new security tests pass and the three pre-existing test modules continue to fail
collection. Those three failures predate this work and are explained in section 3.3. Coverage is
reported, not gated.

### 2.4 Dependency vulnerability gate

Fifteen advisories cannot be patched on this runtime, so the gate suppresses exactly those fifteen
and fails on anything else. Section 3.1 lists each one with its reachability assessment, and the
decision log's register in section 2.2 carries the justification and the review trigger for each.

```bash
pip freeze > /tmp/frozen.txt
pip-audit --strict --no-deps -r /tmp/frozen.txt \
  --ignore-vuln PYSEC-2026-1325 --ignore-vuln PYSEC-2026-2132 \
  --ignore-vuln PYSEC-2026-161  --ignore-vuln PYSEC-2026-248 \
  --ignore-vuln PYSEC-2026-249  --ignore-vuln PYSEC-2026-2280 \
  --ignore-vuln PYSEC-2026-2281 --ignore-vuln PYSEC-2026-2275 \
  --ignore-vuln PYSEC-2026-141  --ignore-vuln PYSEC-2026-142 \
  --ignore-vuln PYSEC-2026-1374 --ignore-vuln PYSEC-2026-1375 \
  --ignore-vuln PYSEC-2026-1845 --ignore-vuln PYSEC-2026-2270 \
  --ignore-vuln GHSA-6v7p-g79w-8964
```

This is the command `.github/workflows/ci.yml` runs, and `backend/tests/security/test_config_guards.py`
compares the workflow's suppression set against the register in both directions, so neither can move
without the other.

Measured on 2026-08-02: `No known vulnerabilities found, 15 ignored`, exit 0. The gate was verified
in both directions — without the suppression list the same command reports `Found 15 known
vulnerabilities in 9 packages` and exits 1, so it detects rather than merely passes. A gate verified
only to pass is not a gate. The reported set and the suppressed set match exactly, which is what
makes a newly published advisory fail the build instead of being absorbed by an entry written for
something else.

The advisory database is a moving target, and the gate is built to fail when it moves. Re-running
it today reports newly published advisories in the audit and test tooling and in one runtime pin.
That is the gate detecting, not a regression in this change set. `.github/workflows/ci.yml` also
carries a staleness check that fails when a suppressed identifier stops being reported, so the
suppression list cannot quietly rot. Every new finding needs its own decision-log entry before it
is suppressed.

One naming detail is worth stating, because an earlier version of this document got it backwards.
The tool reports Python advisory database identifiers, and it *does* match a suppression given as a
GitHub advisory alias — measured, and recorded in DL-12. The gate depends on that behaviour: the
`msgpack` advisory has no `PYSEC-` form at all, so `GHSA-6v7p-g79w-8964` is the only identifier that
can express it, which is why DL-09 permits the mixed namespace. Copy the identifiers exactly as
written above. The real failure mode is a typo: the tool accepts an identifier it does not recognise
and silently suppresses nothing, turning a mistyped entry into a hole rather than an error, which is
why the workflow shape-checks every identifier and cross-checks the register.

### 2.5 Style check

The pipeline runs this, and creating the dependency manifest made it execute for the first time.

```bash
cd backend && flake8 .
```

Baseline: 129 findings, of which 8 are substantive and 4 are undefined names. After this work the
undefined-name count falls from four to one, and the one that remains is the out-of-scope case in
the subscriptions endpoint. No new category appears. **This command exits non-zero both before and
after.** A green pipeline is not on offer, and section 3.3 explains why.

### 2.6 The three repository scans

The three scans below are the effectiveness metrics, made executable. All three run in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml), which is the authoritative definition of
each pattern.

| Gate | What it checks | Before | Required after |
| --- | --- | --- | --- |
| One | Credential patterns across tracked repository content | 4 | 0 |
| Two | Client-secret patterns anywhere under `frontend/` | 0 | must remain 0 |
| Three | Browser storage anywhere under `frontend/src/` | 3 | 0 |

Gate one flags the well-known default PostgreSQL credential pair, an inline SQL password literal,
an assigned signing-key value, and any connection URL carrying an embedded password. It also flags
an assigned value for any variable whose name ends in a credential word, and any inline private
key. Its four original hits were the Compose environment block and three lines of the development
setup script. Read the workflow for the exact pattern; this document describes it rather than
reproducing it, for the reason given at the end of this section.

Gate two is a regression gate rather than a remediation gate. The property already held, since the
frontend only ever used the public client identifier, and the pipeline step converts it from an
accident into an invariant.

Gate three had three hits, all in the frontend authentication service, one each for writing,
removing, and reading the stored token.

Gates two and three are scoped to the frontend, so they can be run directly:

```bash
grep -rIn -E "CLIENT_SECRET|client_secret" frontend/
grep -rIn -E "localStorage|sessionStorage" frontend/src/
```

The pipeline runs broader variants of both, and it restricts gate one to tracked content so that a
local `.env` or an installed dependency tree cannot produce a false hit.

**The credential-scan step must exclude the files that define or document its own pattern.** A
scan whose pattern is itself a credential-shaped string matches the line that declares it, so the
gate can never reach zero otherwise. The workflow filters out its own pattern-defining line, and
this document describes gate one in prose instead of reproducing it. The decision log carries the
reasoning.

### 2.7 Infrastructure validation

```bash
terraform fmt -check
terraform validate
```

**Expected: failure today, for two reasons unrelated to this work.**
`infrastructure/terraform/outputs.tf` references seven resources that `main.tf` never declares:
three storage buckets, two messaging topics, and two functions. Separately, `main.tf:34` reads
`var.gke_num_nodes`, which `variables.tf` declares nowhere. The formatting check reports the outputs
file only; the two changed files pass it. Validate the changed database resources in isolation and
treat both blockers as separate cleanup. Measured that way — the two changed files copied into a
scratch module with a stub for the undeclared variable — `terraform validate` returns success, and a
plan run without the application role's password stops at `No value for required variable` rather
than falling back to one. Naming this now is more useful than reporting a failure later and calling
it a regression.

### 2.8 Manual verification

- Inspect the cross-origin response headers for an allow-listed origin and for a foreign one.
- Confirm the session cookie carries all three attributes, and that no token appears in any
  script-readable browser storage.
- Confirm the failed-login response becomes a throttle response on the sixth attempt.
- Confirm a forced internal error returns the generic envelope with no internal detail.

### 2.9 One scan that cannot be run

A frontend dependency audit needs a clean install from a lock file. No lock file is tracked, so no
reproducible frontend advisory report is obtainable. Frontend posture rests instead on the exact
`axios` pin and on gates two and three.

---

## 3. Residual-risk register

### 3.1 The Python 3.9 remediation ceiling

The runtime ceiling is the most consequential finding in the version analysis, and it reframes what
"patched" can mean for this project.

An audit of the resolved dependency closure reports fifteen advisories in nine packages. For every
one of them, the release that fixes the advisory **cannot be installed on Python 3.9**. Each fix
version was probed directly and each probe returned a `Requires-Python` rejection. A control test
confirmed those rejections are genuine version gates rather than a network artifact: the pinned
versions download cleanly from the same index in the same session.

Ten of the fifteen reach the closure through the application's own runtime dependencies. The
remaining five, listed separately below, arrive through the audit and test tooling or through the
`python-dotenv` pin, and none of them is reachable from the served application at all.

| Package | Pinned | Advisory | Fix release | Installable here | Reachability |
| --- | --- | --- | --- | --- | --- |
| `starlette` | 0.49.3 | PYSEC-2026-161 | 1.0.1 | No | Partial. Host-header URL reconstruction without validation. No application code relies on the reconstructed URL or the Host header. Host-allow-list middleware ships in the pinned version as an optional compensating control |
| `starlette` | 0.49.3 | PYSEC-2026-249 | 1.3.1 | No | Unreachable. Form-parsing limits ignored for URL-encoded bodies. No form parsing anywhere, and the multipart package is absent |
| `starlette` | 0.49.3 | PYSEC-2026-248 | 1.3.0 | No | Low, partial. A request path not beginning with a slash can shift the authority boundary during URL reconstruction. Same non-reliance as PYSEC-2026-161 |
| `starlette` | 0.49.3 | PYSEC-2026-2281 | 1.1.0 | No | Doubly unreachable. Static-file path traversal specific to Windows. No static-file mount exists, and deployment is Linux containers |
| `starlette` | 0.49.3 | PYSEC-2026-2280 | 1.1.0 | No | Unreachable. Unrestricted handler selection in the class-based endpoint API. This application uses decorator routes exclusively |
| `ecdsa` | 0.19.2 | PYSEC-2026-1325 | none, and none will ship | n/a | Unreachable. Timing side channel in elliptic-curve signing. This application signs with HMAC-SHA256 and never invokes the affected path |
| `click` | 8.1.8 | PYSEC-2026-2132 | 8.3.3 | No | Unreachable. Command injection in the editor helper. Arrives transitively through the server and the test client; never called |
| `requests` | 2.32.5 | PYSEC-2026-2275 | 2.33.0 | No | Unreachable. Predictable temporary filename in an archive helper, requiring a local attacker. The application calls only the HTTP verb helpers |
| `urllib3` | 2.6.3 | PYSEC-2026-142 | 2.7.0 | No | Unreachable. Over-decompression requiring an optional compression backend that is not installed |
| `urllib3` | 2.6.3 | PYSEC-2026-141 | 2.7.0 | No | Unreachable. Header leakage on cross-origin redirect through a proxy manager configuration this application never uses |

Eight of those ten are unreachable, one is low and partial, and one is partial with a named
compensating control.

The five that arrive through tooling rather than through the application:

| Package | Pinned | Advisory | Fix release | Installable here | Reachability |
| --- | --- | --- | --- | --- | --- |
| `msgpack` | 1.1.2 | GHSA-6v7p-g79w-8964 | 1.2.1 | No | Unreachable from the application. A reused `Unpacker` can crash after an error while decoding untrusted input. Enters through `pip-audit` only, via `CacheControl[filecache]`; the sole importer deserializes the audit tool's own HTTP response cache. The backend holds zero references to `msgpack`. This advisory has no `PYSEC-` form, which is why the gate carries a `GHSA-` entry |
| `filelock` | 3.19.1 | PYSEC-2026-1375 | 3.20.1 | No | Unreachable from the network. A time-of-check-to-time-of-use symlink race during lock-file creation lets a **local** attacker truncate a file. Enters through `pip-audit` only; the backend holds zero references to `filelock` |
| `filelock` | 3.19.1 | PYSEC-2026-1374 | 3.20.3 | No | Doubly unreachable. The race is specific to `SoftFileLock`, and the cache selects `FileLock` instead. Local attack vector, scored 5.6 Medium |
| `pytest` | 8.4.2 | PYSEC-2026-1845 | 9.0.3 | No | Unreachable from the network. A predictable temporary directory lets a local user cause denial of service. Test-runner only; the container command runs `uvicorn`, so the runner never executes in a deployed environment. This one is the clearest argument for keeping development tooling out of the production image |
| `python-dotenv` | 1.2.1 | PYSEC-2026-2270 | 1.2.2 | No | Unreachable. `set_key()` and `unset_key()` follow symbolic links when **rewriting** a `.env` file. Pydantic calls the read helper only, and `backend/` holds zero references to `dotenv`, `set_key` or `unset_key`. Local access plus operator interaction, scored 5.9 Medium |

Thirteen of the fifteen are unreachable, one is low and partial, and one is partial with a named
compensating control. Not one is reachable by an unauthenticated network caller against the served
application.

The single advisory that will never receive a patch is the `ecdsa` timing side channel, and it is
unreachable by construction. This application signs tokens with HMAC-SHA256. The settings class
restricts the algorithm to the HMAC family, which turns that from an assumption into an enforced
invariant. No configuration change can quietly move signing onto the affected code path.

**Review trigger, identical for all fifteen: a Python runtime upgrade.** At that point the
suppression list should be emptied and the pins raised, and each advisory re-measured rather than
re-accepted. Accepting an advisory without a scheduled reconsideration is how a temporary exception
becomes permanent. Advisory data is a point-in-time snapshot, so the inventory needs re-measuring at
every security review rather than copying forward.

The upgrade is not performed here. Python 3.9 is hardcoded in four places: the backend container
image, the pipeline's Python setup step, a Cloud Function runtime identifier in Terraform, and the
deployment script. None of the four is among the twelve findings, and changing them would breach
the minimal-change constraint in the most direct way available. Section 4 names the upgrade as the
highest-priority follow-on.

### 3.2 The four partial remediations

Four findings cannot be fully closed within a minimal boundary. Each is labelled partial here
because claiming otherwise would be the more serious failure.

**SEC-07 gained throttling, not durable lockout.** The limiter keeps its state in process, so that
state is per-worker and lost on restart. Lockout is therefore neither durable nor
multi-replica-safe. Durable lockout needs either new database columns, which require migration
tooling this repository does not have, or an external store, which was ruled out as new
infrastructure.

**SEC-10 gained encryption, not certificate verification.** Both ends now require encryption: the
Cloud SQL instance is set to accept encrypted connections only, and the application requests
`require` explicitly instead of inheriting the negotiated default. `require` guarantees encryption
and performs no server-identity check. Moving to `verify-full` with a distributed, rotatable root
certificate is the recommended follow-on, and it is item 3 in section 4.

**SEC-11 gained role separation, and least-privilege grants in one place only.** The two halves
differ, so they are stated separately.

*Locally, the grants are delivered and verified.*
[`scripts/setup_dev_environment.sh`](scripts/setup_dev_environment.sh) replaces the single
all-privileges account with an owner role that performs schema work and an application role limited
to `CONNECT`, schema `USAGE`, and `SELECT`, `INSERT`, `UPDATE`, `DELETE` on tables plus `USAGE`,
`SELECT` on sequences. `REVOKE CREATE ON SCHEMA public FROM PUBLIC` removes the default grant that
would otherwise hand the application role the DDL those grants withhold, and two
`ALTER DEFAULT PRIVILEGES` statements extend the same data operations to tables the owner creates
later. `GRANT ALL PRIVILEGES` appears nowhere.

*On Cloud SQL, the declaration separates the account and restricts nothing.*
[`infrastructure/terraform/main.tf`](infrastructure/terraform/main.tf) declares
`google_sql_user.app` with its name and password from input variables, so the application no longer
shares the instance admin account. Two facts bound what that declaration can achieve. Cloud SQL
grants `cloudsqlsuperuser` to every built-in PostgreSQL user it creates, and the Terraform Google
provider exposes no resource for a `GRANT` or a `REVOKE`. A default `terraform apply` therefore
creates a working but elevated account, and no Terraform argument narrows it.

Restriction has to arrive out of band. Connect to `main-database` as the instance admin and run:

```sql
REVOKE cloudsqlsuperuser FROM app_user;
ALTER ROLE app_user NOCREATEDB NOCREATEROLE;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE "main-database" TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_user;
```

Substitute the value of `db_app_user` if it is not the default. The privilege set mirrors the local
one the provisioning script issues and verifies; unlike that one, it was not executed against a
Cloud SQL instance in this work, because no instance is provisioned here. Until an operator runs it,
the cloud application role keeps the role-creation, database-creation and DDL rights the automatic
grant confers. `backend/tests/security/test_config_guards.py` asserts that this block still carries
every statement, and that the declaration carries no role-assignment argument that a default apply
could not satisfy.

*Row-level security is not delivered, on either side.* Per-tenant policies need a policy per table
plus a session-variable convention, which is a data-layer redesign.

**SEC-12 gained custody discipline, not a secret store.** Section 1.3 has the detail.

### 3.3 Other residual risks

**No tracked frontend lock file, so transitive resolution is not deterministic.** Direct
dependencies are pinned exactly. Generating a lock file would commit a full transitive tree that
this work has not audited, and no audit is reproducible without first generating it. Lock-file
generation is item 2 in section 4.

**The cookie migration created a cross-site request forgery surface that did not exist before.** A
bearer header resists forgery inherently, because script must attach it deliberately. A cookie
travels automatically. `SameSite=Strict` is the control. A full anti-forgery token scheme would
touch every mutating endpoint and every client call site, which is the opposite of minimal, so the
gap is recorded here rather than closed.

**Enabling credentialed mode activates an `axios` advisory that was dormant.** CVE-2023-45857
(High, 7.1, CWE-359) affects `axios` 1.0.0 through 1.5.1. In those versions the browser request
adapter attaches a cross-site header carrying a cookie value to every request once credentialed
mode is on.

No vulnerable `axios` is installed, and the declared range never resolved to one. The real defect
was narrower: the declared floor sat inside the advisory range with no lock file, so resolution was
not deterministic. A stale cache or an offline mirror could legitimately produce an affected
release.

Two controls close it. The dependency is pinned exactly to 1.19.0, which separates the two
concerns. The explicit cross-site-token option is deliberately left unset, which keeps the old
behaviour switched off.

**Three endpoints cannot persist records, before or after this work.** `POST /listings/`,
`POST /subscriptions/` and `POST /filters/` all fail for reasons that have nothing to do with
security.

- `POST /listings/` — the listing model has no owner column, and two non-null timestamp columns are
  never supplied.
- `POST /subscriptions/` — the subscription model has no plan column, and a non-null status column is
  never supplied.
- `POST /filters/` — `filters.py:20` assigns `FilterCreate` models to the mapped `criteria`
  relationship, which expects `Criteria` rows, and supplies no value for the non-null `created_at`
  column. The request is validated and rejected-on-unknown-keys correctly, then the flush fails. The
  route answers the uniform sanitized 500 of section 2 and **leaves no row**, which
  `test_filter_creation_defect_answers_a_sanitized_fault` asserts together with a zero-row check.

Repairing any of the three means adding or retyping columns, which needs migration tooling this
repository does not have, and that is feature work rather than security work.

The honest criterion is narrower: all three routes stay importable with their paths, verbs and
request contracts unchanged; the new strict schemas close the mass-assignment vector on them; and
the failure discloses nothing, because it surfaces through the same sanitized envelope every other
error uses.

**The pre-existing pipeline baseline, measured so that "no new failures" is an honest claim.**
Style checking reported 129 findings before this work. The test suite collected zero tests with
three collection errors, because all three existing test modules failed to import. The pipeline had
never reached either step, because it failed at dependency installation.

Those three collection errors survive this work untouched. **A green pipeline is not on offer.**

**The frontend does not type-check or build**, for reasons unrelated to security. Two packages are
imported but declared nowhere. One service module holds component markup and extends a component
base class in a file whose extension cannot compile either. Several modules import through
absolute paths that the TypeScript path configuration does not map. The pipeline invokes a lint
script that the package manifest does not define.

The SEC-06 acceptance criterion is therefore verified by code inspection and by the backend cookie
tests, not by a green frontend build.

### 3.4 Weaknesses found and deliberately not fixed

Seven further weaknesses surfaced during the work. None is among the twelve findings, and the
minimal-change constraint forbids widening scope, so each is recorded here rather than fixed. Each
also carries a decision-log entry.

| Observation | Why it is not fixed here |
| --- | --- |
| The Zillow client sends its API key as a URL query parameter, where it lands in logs and proxy records | Changing it alters an external integration contract |
| Deployed functions permit unauthenticated invocation, in both the deployment script and the Terraform configuration | Infrastructure authorization work |
| The container cluster has neither private networking nor authorized-network restrictions | Network architecture work |
| Pipeline actions are pinned to mutable major tags rather than immutable digests | Supply-chain hardening |
| The database proxy image is superseded | Base-image currency |
| Both container base images are past end of life | The runtime version freeze applies; see section 3.1 |
| Containers run as the root user | Container hardening |

An eighth observation was closed rather than deferred. The outbound user schema previously
declared the password hash field, and that field is gone, removed alongside the SEC-02 identity
correction because the same model was already being changed.

One further note, recorded rather than acted on: the application exposes interactive API
documentation by default. That is normal for this framework and may well be intentional. Gating it
in production is a one-line change whenever the team decides it should be gated.

---

## 4. Deferred follow-ons, in priority order

1. **Migrate to Python 3.10 or newer. That upgrade is the single highest-priority follow-on.** The
   upgrade is the only real remedy for the fifteen advisories in section 3.1, every one of which has
   a fix release that the current runtime refuses to install. Section 3.1 is the justification. On
   completion, empty the suppression list and raise the pins.
2. Generate and commit a frontend lock file after auditing the transitive tree, and declare the two
   packages that are imported but never declared.
3. Move database transport to `verify-full` with a distributed, rotatable root certificate, so the
   connection verifies server identity and not only encryption.
4. Provision a managed secret store with key management, and migrate the deployment pipeline to
   federated identity in place of the long-lived service-account key.
5. Add per-service database roles and row-level security.
6. Add a full anti-forgery token scheme, replacing reliance on `SameSite=Strict` alone.
7. Add durable, multi-replica-safe account lockout, which needs either migration tooling or an
   external store.
8. Repair `infrastructure/terraform/outputs.tf` so that plan validation succeeds.
9. Harden the containers: refresh both base images, run as a non-root user, pin pipeline actions to
   immutable digests, and refresh the database proxy image.

---

## 5. Breaking changes

There is exactly one.

**Previously issued tokens become invalid.** The subject claim changes from an email address to
the numeric primary key, because the verification path compares that claim against an integer
column. Any token still carrying an email fails verification.

No gentler option exists. Accepting both claim shapes during a transition window would keep the
broken comparison path alive for the length of the window, and that path is the vulnerability. A
window that preserves the defect is not a mitigation. Reversing the change instead, by matching on
email, would key authentication to a mutable field and contradict the model's own primary key. The
reporter accepted this consequence in the original brief.

Operationally: deployment is coordinated rather than zero-downtime, and active users
re-authenticate once.

**One change looks like a break and is not.** The application refuses to start when the origin
allow-list is missing, wildcarded, or malformed. That is the stated acceptance criterion and the
correct fail-closed behaviour. An unavailable service is preferable to one that accepts
credentialed requests from any origin. The practical consequence is that a configuration error
surfaces as a failed deployment rather than as a silent weakening, so validate the allow-list
against the deployed frontend origins before rollout.

Everything below is preserved:

- Every route path and every HTTP verb. One route is added, `POST /auth/logout`, because a browser
  cannot delete a cookie it cannot read.
- Every request contract.
- Both authentication response body shapes, key for key. The session cookie is set alongside the
  existing body, not instead of it.
- The declared response model on the filter endpoint.
- All eight pre-existing environment variable names. Every new setting is additive.
- The public listing read path with its `skip` and `limit` pagination, and its public access.
- The Redux store shape and the single-page application routing.
- The Zillow ingestion scheduling and transform logic.
- The PayPal sandbox checkout experience.
- The database schema. No column was added or altered.

---

## 6. Rollback

Every change is additive, a pin, or a configuration value, so reverting means reverting the commit
and restoring the previous environment values alongside it.

Configuration-only changes revert through environment values with no code deployment. The origin
allow-list and the database SSL mode both fall into that category.

One consequence is not reversible. Tokens issued under the corrected subject claim become invalid
on rollback, so users re-authenticate a second time. That is inherent to correcting an identity
claim, and it is recorded here as a deployment note rather than presented as clean.

---

## 7. Compliance context

Three frameworks are named below as context for why these fixes matter. **No certification,
assessment, or attestation claim is made or implied.**

**GDPR and CCPA** concern the personal data this application stores. Email addresses and credential
hashes are personal data. Three of the twelve findings therefore touch obligations around
protecting it: the credential exposure, the cleartext database transport, and the over-privileged
database account.

**PCI DSS** concerns the payment path. An integration hardcoded to a test environment cannot be
operated correctly, and the same code path holds client credentials. The fix moves the environment
to validated configuration and adds a pipeline gate that keeps the client secret out of
browser-delivered code.

What this work does not do: no gap assessment, and no evidence produced for an assessor. It
addresses nothing about data-subject rights, retention, deletion, breach notification, cardholder
data storage, or network segmentation. Several of those depend on controls this work explicitly
defers, including a managed secret store, certificate-verifying transport, and per-service
database roles.

A framework name in a technical document is context, not a compliance claim.

---

## Reporting a vulnerability

<!-- MAINTAINER: replace the line below with the real security contact before publishing. -->

Security contact: **not yet established for this repository.** A maintainer must add a reporting
address and a response expectation here; this document deliberately invents neither.
