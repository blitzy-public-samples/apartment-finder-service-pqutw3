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
  maps findings to files in both directions. Its section 3.1 carries the coverage as measured: 82
  edges in each direction with an empty difference both ways.

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

**Supply the two frontend build variables to the build, not to the runtime.** `REACT_APP_API_BASE_URL`
and `REACT_APP_PAYPAL_CLIENT_ID` are read by the browser sources, and create-react-app substitutes
them into the bundle while it compiles. A value handed to a running container arrives too late.
`infrastructure/docker/Dockerfile.frontend` declares one build argument per name ahead of
`npm run build`, and `infrastructure/docker/docker-compose.yml` forwards both with no inline default.
Whatever they hold is served to every visitor, so neither may carry a secret; the PayPal client
**secret** stays a backend setting and never becomes a build argument.

[`.env.example`](.env.example) is authoritative for every variable name, shape, and purpose. It
carries two contracts: the backend settings the process reads, and a final section for the two
frontend build variables. It documents the JSON-array form the origin allow-list requires, the
per-algorithm key floor, and the one local-development exception for the database SSL mode.

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

**Version control is not the only way a local secret escapes.** Both container definitions copy their
whole build context with `COPY . .`, so an untracked `.env` that `.gitignore` keeps out of history
still lands in an image layer. Three context-local ignore files close that path: one at the
repository root and one at each declared build context, `backend/` and `frontend/`. Each excludes the
environment file and its temporary form, the `secrets/` directory, certificates, keys, credential
JSON, virtual environments, dependency trees, caches and coverage output.
`test_config_guards.py` asserts the exclusion of every one of those classes per context, and asserts
that the exclusions still admit the files each build needs.

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
- The broad `COPY . .` in both container definitions is unchanged, so the build depends on the
  context exclusions rather than on an allow-list. Narrowing each copy to the application sources is
  the stronger form, and section 4 carries it as a follow-on; `DL-129` carries the decision.
- The deployment pipeline still authenticates with a long-lived service-account key rather than
  federated identity. `.github/workflows/cd.yml` passes that key to the Cloud SDK setup step and
  exports it as the default credential. Section 4 carries the migration as a follow-on, and `DL-253`
  carries this partial remediation's boundary.

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
nineteen packages directly, fourteen for the runtime and five for test and audit tooling.

Two closure numbers matter, and confusing them understates what the audit covers. Installing the
fourteen runtime pins alone resolves to **42 packages**. Installing the whole manifest, which is what
a developer and the pipeline both do, produces an environment that `pip freeze` reports as **74
packages** — and `pip freeze` is exactly what the dependency gate in section 2.4 reads, so 74 is the
audited surface, not 42. Both figures were measured on Python 3.9.25. Everything beyond the nineteen
direct pins arrives transitively, pinned by the resolution rather than by hand, which is the right
granularity without a lock file.

### 2.2 Security regression tests

The primary gate for eleven of the twelve findings.

```bash
cd backend && python -m pytest tests/security -q
```

Measured: **689 passed**, no failures. The suite covers the identity claim, the origin allow-list,
the password policy, request validation, cookie attributes, login throttling, the error boundary, the
configuration guards, the charge seam, the provisioning script's publish and privilege statements,
the build definitions, and the provider lock.

### 2.3 Full suite with coverage

This matches the pipeline invocation. **The last flag is not optional.**

```bash
cd backend && python -m pytest --cov=./ --cov-report=xml --continue-on-collection-errors
```

Measured: **689 passed with 3 collection errors**, exit 1. The three errors are the pre-existing test
modules explained in section 3.3. Coverage is reported, not gated.

Without `--continue-on-collection-errors` the same command exits 2 with
`Interrupted: 3 errors during collection` and runs **zero tests** — the three pre-existing modules
fail to import during collection, and pytest then abandons the run before reaching the security
suite. A command that appears to run the tests while running none is worse than one that fails, which
is why the flag belongs in the documented invocation and in the pipeline.

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

Measured again on 2026-08-03: `No known vulnerabilities found, 15 ignored`, exit 0. The gate was
verified in both directions — without the suppression list the same command reports `Found 15 known
vulnerabilities in 9 packages` and exits 1, so it detects rather than merely passes. A gate verified
only to pass is not a gate. The nine packages are `click`, `ecdsa`, `filelock`, `msgpack`, `pytest`,
`python-dotenv`, `requests`, `starlette` and `urllib3`, and the fifteen identifiers reported are
exactly the fifteen suppressed — no more and no fewer. That parity is what makes a newly published
advisory fail the build instead of being absorbed by an entry written for something else.

The advisory database is a moving target, and the gate is built to fail when it moves. Every new
finding needs its own decision-log entry before it is suppressed.

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) also carries a staleness check for the
opposite direction. It reads the audit's own JSON report, collects both `id` and `aliases` from every
reported advisory, and fails naming any declared suppression that no longer appears in either. Reading
aliases as well as identifiers is what covers the `msgpack` entry, which exists only under the GitHub
namespace. Verified in both directions by executing the shipped check against the real report and
against a report with a declared identifier removed; `DL-345` carries the decision.

One naming detail is worth stating. The tool reports Python advisory database identifiers, and it
*does* match a suppression given as a GitHub advisory alias; that behaviour is measured and recorded
in `DL-12`. The `msgpack` advisory has no `PYSEC-` form at all, so `GHSA-6v7p-g79w-8964` is the only
identifier that can express it, and `DL-09` carries the mixed namespace.

Copy the identifiers exactly as written above. The failure mode a typo produces is silent: the tool
accepts an identifier it does not recognise and suppresses nothing. The workflow therefore
shape-checks every identifier and cross-checks the register, per `DL-402` and `DL-205`.

### 2.5 Style check

The pipeline runs this, and creating the dependency manifest made it execute for the first time.

```bash
cd backend && flake8 .
```

Baseline: 129 findings, of which 4 are undefined names. Measured again on 2026-08-03: **108 findings,
of which 4 are substantive and exactly 1 is an undefined name** — `datetime` at
`app/api/endpoints/subscriptions.py:60`, the out-of-scope case section 3.3 records. The other three
are unused imports in `app/api/endpoints/listings.py`, `app/tasks/listing_updater.py` and
`tests/test_api.py`. The remaining 104 are blank-line, trailing-whitespace, line-length and
missing-final-newline findings in files this work did not reformat.

No new category appears: the category set is the same seven as the baseline. Both figures were
measured by running the command above, the baseline against the tree as it stood before this work.
**This command exits non-zero both before and after.** A green pipeline is not on offer, and section
3.3 explains why.

### 2.6 The three repository scans

The three scans below are the effectiveness metrics, made executable. All three run in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml), which is the authoritative definition of
each pattern.

| Gate | What it checks | Scope | Before | Required after |
| --- | --- | --- | --- | --- |
| One | Credential patterns | every tracked file, this workflow included | 4 | 0 |
| Two | Client-secret patterns | all of `frontend/`, excluding `node_modules/`, `build/` and `coverage/` | 0 | must remain 0 |
| Three | Browser token storage | all of `frontend/`, same three exclusions | 3 | 0 |

Gate one flags the well-known default PostgreSQL credential pair, an inline SQL password literal,
an assigned signing-key value, and any connection URL carrying an embedded password. It also flags
an assigned value for any variable whose name ends in a credential word, and any inline private
key. Its four original hits were the Compose environment block and three lines of the development
setup script.

Gate two matches `client_secret` and `paypal_secret` in either hyphen or underscore spelling, with
or without the separator, case-insensitively. It is a regression gate rather than a remediation
gate: the property already held, since the frontend only ever used the public client identifier, and
the pipeline step converts it from an accident into an invariant.

Gate three matches six storage mechanisms, not two: `localStorage`, `sessionStorage`, `indexedDB`,
`Storage.prototype`, `document.cookie` and `window.name`. Its three original hits were in the
frontend authentication service, one each for writing, removing and reading the stored token.

**Gate one excludes no file, and it runs in two stages.** The first stage is the pattern, written
with one-character bracket expressions — `[:]` for a colon, `[W]` for a W, `[w]` for a w — so it
matches the same text without matching the line that declares it. That property is what lets the gate
cover the workflow and this document as well; `DL-207` carries it.

The pattern matches an assignment with or without spaces around the separator and with or without a
quote, so the formatter-compliant spelling `NAME = "value"` does not pass, and it covers the lower-case
spelling when the value is quoted. Gate one reads tracked content only, so a local `.env` or an
installed dependency tree produces no false hit.

The second stage is a reviewed allow-list, which is what keeps a pattern this broad from reporting
legitimate content. It admits four classes:

- a value read from configuration rather than written in the file: `= settings.`, `os.`, `var.`,
  `process.`, `self.`;
- a name that denotes a policy bound or a piece of metadata rather than a secret: `MIN_LENGTH`,
  `MAX_BYTES`, `UPPERCASE`, `LOWERCASE`, `DIGITS`, `SPECIAL_CHARACTERS`, `_VARIABLE`, `_ARGUMENT`,
  `_FIELD`, `_LITERAL`, `_REFERENCE`, `_PATTERN`;
- an upper-case placeholder token, of the form an example file uses in place of a real key;
- a line carrying the reviewed-line marker with a reason beside it.

The workflow holds the marker's exact text and this document does not reproduce it, as it does not
reproduce the pattern: a line quoting either would be matched or admitted by it. `DL-208` carries the
pattern's breadth and the four spellings left uncovered.

Measured on 2026-08-03: the pattern matches **21 lines**, the allow-list admits all 21, and the gate
reports **0**. Of the 21, five are the password-policy bounds in the request schema, three are values
read from `settings.`, eight are constants and controls inside the guard tests, one is a line in the
requirements document, and four are the marked lines. The marker appears on exactly **four**
test-fixture passwords, all under `backend/tests/`, and on **no line of application source**.
`backend/tests/security/test_config_guards.py` pins that count at four and requires every marked line
to carry a reason and to be matched by the pattern. It also asserts that the allow-list admits no
credential shape from its own positive-control set.

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) holds the exact expression for all three, and
this document describes rather than reproduces gate one: a pattern built from credential-shaped
strings would match the line quoting it, and gate one reads this file. The decision log carries the
reasoning. To run gates two and three by hand, use the two commands from the workflow verbatim;
narrowing either scope or shortening either pattern gives a weaker answer than the pipeline's.

### 2.7 Infrastructure validation

```bash
terraform fmt -check
terraform validate
```

**Expected: failure today, for two reasons unrelated to this work.**
`infrastructure/terraform/outputs.tf` references seven resources that `main.tf` never declares:
three storage buckets, two messaging topics, and two functions. Separately, `main.tf:45` reads
`var.gke_num_nodes`, which `variables.tf` declares nowhere. The formatting check reports the outputs
file only; the two changed files pass it.

Validate the changed database resources in isolation and treat both blockers as separate cleanup.
`DL-256` carries the decision to leave the outputs file alone.

Measured that way — the two changed files copied into a scratch module with a stub for the undeclared
variable — `terraform validate` returns success. A plan run without the application role's password
stops at `No value for required variable` rather than falling back to one.

**The provider is bounded and locked.** `main.tf` declares `hashicorp/google` at `~> 7.42` and bounds
the command line at `>= 1.11.0, < 2.0.0`. The write-only password argument needs that floor. Under
both upper bounds, a major release that withdraws `ssl_mode`, `password_wo` or `password_wo_version`
fails installation rather than applying; `DL-350` and `DL-368` carry the bounds and the lock.

[`infrastructure/terraform/.terraform.lock.hcl`](infrastructure/terraform/.terraform.lock.hcl) is
tracked and carries one directory hash for each platform an operator or the pipeline installs from —
`linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64` — beside the registry checksum set.
Regenerate it after any constraint change, and commit the result:

```bash
cd infrastructure/terraform
terraform providers lock \
  -platform=linux_amd64 -platform=linux_arm64 \
  -platform=darwin_amd64 -platform=darwin_arm64
```

Measured: the lock records version 7.42.0 under constraint `~> 7.42`, with four directory hashes and
twelve registry checksums, and `terraform init -backend=false` selects that build. A checkout on a
platform the lock omits fails installation rather than accepting an unverified provider.

**Supply the application role's password through the environment or an ignored file, never on the
command line.** `TF_VAR_db_app_password` and a gitignored `*.tfvars` file passed with `-var-file` are
the two supported channels. A value passed with `-var` appears in the process arguments, which any
local user can read for the life of the command, and in shell history afterwards. `.gitignore`
excludes `*.tfvars` and `*.tfvars.json` while admitting `*.tfvars.example`, so a template stays
committable and a filled-in file cannot be committed.

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

The five that sit outside the served application. Four arrive through the audit and test tooling; the
last arrives through the direct `python-dotenv` pin, which `pydantic` reads to load `env_file`:

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

Account throttling also brings a denial-of-service surface that did not exist before this work, and
it is the price of counting per account rather than per address. The counter reserves one of the
account's five attempts before the credential lookup runs, which is what stops an attacker learning
whether an address is registered. An unauthenticated attacker who knows a victim's address can
therefore spend that budget and leave the owner answered with 429 for the rest of the window, and
repeat it indefinitely. `DL-292` carries the two-layer decision and `DL-337` the keying.

A second variant targets the tracking map rather than one account. The map holds 4,096 accounts and
never evicts an entry that has reached the limit. An attacker who drives 4,096 distinct accounts to
the limit therefore denies a tracking slot to any further account, whose first attempt is refused
until an entry expires. Reaching that state needs roughly 4,096 distinct source addresses, because
the address-keyed limiter allows only five attempts per address per window. `DL-49` carries that
bound, and both variants close with the durable store in item 8 of section 4.

**SEC-10 gained encryption, not certificate verification.** Both ends now require encryption: the
Cloud SQL instance is set to accept encrypted connections only, and the application requests
`require` explicitly instead of inheriting the negotiated default. `require` guarantees encryption
and performs no server-identity check. Moving to `verify-full` with a distributed, rotatable root
certificate is the recommended follow-on, and it is item 3 in section 4. That change sets
`DB_SSLMODE=verify-full` and passes the certificate-authority path as `sslrootcert` in the engine
connect arguments, or as `PGSSLROOTCERT` in the environment; libpq otherwise reads only
`~/.postgresql/root.crt`.

**SEC-11 gained role separation, and least-privilege grants in one place only.** The two halves
differ, so they are stated separately.

*Locally, the grants are delivered and verified.*
[`scripts/setup_dev_environment.sh`](scripts/setup_dev_environment.sh) replaces the single
all-privileges account with an owner role that performs schema work and an application role limited
to `CONNECT`, schema `USAGE`, and `SELECT`, `INSERT`, `UPDATE`, `DELETE` on tables plus `USAGE`,
`SELECT` on sequences. Two revokes remove what PostgreSQL grants `PUBLIC` by default:
`REVOKE CREATE ON SCHEMA public FROM PUBLIC` and
`REVOKE CONNECT, TEMPORARY ON DATABASE dbname FROM PUBLIC`. Two `ALTER DEFAULT PRIVILEGES` statements
extend the same data operations to tables the owner creates later, and `GRANT ALL PRIVILEGES` appears
nowhere. `DL-36` and `DL-353` carry the two revokes.

The batch does not stop at issuing those statements. It ends with a block that reads the **effective**
access-control lists, or ACLs, and raises if they disagree with the intent. `PUBLIC` must hold nothing
on the database and nothing but `USAGE` on the schema, and the application role must hold `CONNECT`
and schema `USAGE` while holding neither `TEMPORARY` nor schema `CREATE`.

The block substitutes `acldefault` for a null ACL column, since an untouched `datacl` reads as empty
while the default privileges still apply. `psql` runs the batch with the stop-on-error setting, so a
raise aborts provisioning. `DL-354` carries the verification block and `DL-355` the form the suite
reads it in.

Measured against PostgreSQL 13.23, and this is the one measurement behind every privilege figure in
this section: before the revokes, `PUBLIC` held `CONNECT, TEMPORARY` on the database, and a role with
no explicit grant answered true to `CONNECT`, `TEMPORARY` and schema `CREATE`. Afterwards `PUBLIC`
held nothing on the database, `app_user` answered true only to `CONNECT` and schema `USAGE`, and the
owner still connected. Schema `USAGE` is deliberately left with `PUBLIC`: with `CONNECT` revoked, no
unprivileged role reaches the database to use it, and removing it is outside this scope.

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
REVOKE CONNECT, TEMPORARY ON DATABASE "main-database" FROM PUBLIC;
GRANT CONNECT ON DATABASE "main-database" TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO app_user;
```

**A database grants `CONNECT` and `TEMPORARY` to `PUBLIC` by default, so the block above issues both
revokes.** Without the second, every role in the cluster still reaches the database and `app_user`
keeps temporary-object capability beyond the privilege set above. The before-and-after figures are the
ones measured for the local batch earlier in this section; the same statements produce the same
privilege state, and schema `USAGE` is left with `PUBLIC` on this side too.

Verify the effective ACLs rather than trusting the statements: a `GRANT` that silently applied to the
wrong role reads the same as one that worked.

```sql
SELECT coalesce(string_agg(a.privilege_type, ', ' ORDER BY a.privilege_type), 'none')
         AS public_holds_on_database
  FROM pg_database d, aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
 WHERE d.datname = current_database() AND a.grantee = 0;

SELECT has_database_privilege('app_user', current_database(), 'CONNECT') AS connect_granted,
       has_database_privilege('app_user', current_database(), 'TEMPORARY') AS temporary_granted,
       has_schema_privilege('app_user', 'public', 'USAGE') AS schema_usage_granted,
       has_schema_privilege('app_user', 'public', 'CREATE') AS schema_create_granted;
```

Expected: `none`, then `t, f, t, f`. Grantee zero is the `PUBLIC` pseudo-role, and the `acldefault`
substitution is the same one the local batch uses, for the same null-column reason stated there.

Substitute the value of `db_app_user` if it is not the default. The privilege set mirrors the local
one the provisioning script issues and verifies; unlike that one, it was not executed against a
Cloud SQL instance in this work, because no instance is provisioned here. The two revokes and the
verification queries were executed against a local PostgreSQL 13.23 server, which is where the
measurements above come from. Until an operator runs the block, the cloud application role keeps the
role-creation, database-creation and DDL rights the automatic grant confers.
`backend/tests/security/test_config_guards.py` asserts that this block still carries every statement,
and that the declaration carries no role-assignment argument that a default apply could not satisfy.

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

**`COOKIE_SECURE` defaults to true, and the Compose stack serves plain HTTP.** A browser discards a
`Secure` cookie delivered over plain HTTP, so on the default the stack answers a login with 200 and
the frozen body while storing no session cookie, and every protected route then answers 401. The
Compose definition therefore carries `COOKIE_SECURE=${COOKIE_SECURE:-false}` beside the transport
exception, which is the only channel an operator has: the definition declares no `env_file`, and all
three build contexts exclude `.env`.

The default is deliberate and stays true, so a deployment that sets nothing gets the secure
attribute. The residual is the mirror of the transport exception beside it: a local value of `false`
could be copied into a deployed environment by mistake. Both live in the Compose file rather than in
code, so the copy is visible in a diff.

**Logout clears the cookie; it does not revoke the token.** `POST /auth/logout` expires the session
cookie, so the browser stops sending it, and that is the whole of what a server can do about a cookie
it cannot read from script. The token itself stays valid until its `exp` claim passes.

Anything that already holds a copy — a captured `Authorization` header, a proxy log, a token minted
for a non-browser client — continues to authenticate after logout: verification checks the signature
and the expiry and consults no revocation record. Closing that gap needs a `jti` claim plus a
persisted deny list, and `DL-361` carries that boundary. The controls that remain are the short token
lifetime and the `HttpOnly` attribute, which stops script reading the cookie. It does not stop script
seeing a token: the frozen login and register bodies still return `access_token` to page code, and
the remediation removed browser persistence rather than all script access. Read "logout invalidates
the session" as ending the browser's session, not as revocation.

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

**The public listing page has no size ceiling, so one unauthenticated request can read the whole
table.** `GET /listings/` is public by design and its `skip` and `limit` parameters are plain
integers with no declared range, which the brief freezes. Any value the driver binds is therefore a
legal `LIMIT`, and `?limit=1000000000` returns every row (CWE-770).

The bound this work does deliver is narrower than it looks, so read it precisely. A value past the
driver's signed 64-bit range never reaches the database: it answers the uniform sanitized 500 with
no statement, driver name or traceback, which is what `DL-187` measured. That bound holds only
**above** the accepted domain and is not a page-size limit. Measured on PostgreSQL 13.23: `LIMIT` at
9223372036854775807 is accepted and returns the whole table, while a negative `LIMIT` raises
`InvalidRowCountInLimitClause` and reaches the client as the same sanitized 500. On the SQLite test
harness a negative limit instead returns every row, which `DL-67` records; production is PostgreSQL.

No code change is offered here, and that is deliberate. Narrowing the parameters would change a
contract the brief freezes, so `DL-187` refuses it and recommends the amendment instead. Authorising
a bounded page size is item 6 in section 4.

**Two endpoints cannot persist records, before or after this work.** `POST /listings/` and
`POST /subscriptions/` both fail for reasons that have nothing to do with security.

- `POST /listings/` — the listing model has no owner column, and two non-null timestamp columns are
  never supplied.
- `POST /subscriptions/` — the subscription model has no plan column, and a non-null status column is
  never supplied.

Repairing either means adding or retyping columns, which needs migration tooling this repository
does not have, and that is feature work rather than security work.

The honest criterion is narrower: both routes stay importable with their paths, verbs and request
contracts unchanged; the new strict schemas close the mass-assignment vector on them; and the
failure discloses nothing, because it surfaces through the same sanitized envelope every other
error uses.

`POST /filters/` is **not** in that group. It persists. The endpoint copies the validated
allow-list onto mapped `Criteria` children and supplies the server-owned `created_at`, so a valid
request writes one filter row with its criteria rows and returns the declared response model. No
column was added or retyped to make that work, so nothing here depends on migration tooling.
`test_filter_creation_persists_only_the_validated_fields`,
`test_a_created_filter_belongs_to_its_author_alone` and
`test_filter_creation_refuses_a_client_supplied_owner` assert the stored row, its ownership, the
cross-account isolation of the read path, and the refusal of a body naming an owner.

**Payment replay protection is per-worker and bounded, so a reference can authorize a second
charge.** A verified provider reference is recorded in a ledger inside the worker that verified it,
and a replay is refused only while that digest is retained (CWE-294). The ledger holds 4,096
digests, evicts the oldest past that, and starts empty after a restart.

Three states therefore admit a second charge on the same reference: after a worker restart, past the
4,096th distinct reference in one worker, and on any other worker in a multi-replica deployment.
This is the same residual class as the login throttle in section 3.2, from the same cause, and
`DL-163` carries the decision to keep the in-process ledger rather than provision a store. Durable,
shared replay protection is item 9 in section 4.

**Keep `PAYPAL_MODE` at `sandbox` until the subscription schema is repaired.** The setting accepts
`live`, and on `live` the provider captures a real charge. The charge is verified and consumed
before the row is built, and `POST /subscriptions/` then fails at insertion for the schema reasons
above, so the money moves and no record of it survives.

Nothing in the code stops that sequence, because each half is correct on its own: the domain check
exists so an operator can select `live` deliberately, and the persistence gap is feature work the
brief excludes. The two facts only combine into a hazard when the mode is switched, which is why the
warning sits here and beside the variable in `.env.example`.

**The pre-existing pipeline baseline, measured so that "no new failures" is an honest claim.**
Style checking reported 129 findings before this work, 4 of them undefined names. The test suite
collected zero tests with three collection errors, because all three existing test modules failed to
import. The pipeline had never reached either step, because it failed at dependency installation.

Measured now: style checking reports 108 findings with 1 undefined name, and the suite reports 689
passed with the same three collection errors. Those three errors survive this work untouched. **A
green pipeline is not on offer.**

**The frontend does not type-check or build**, for reasons unrelated to security. Two packages are
imported but declared nowhere. One service module holds component markup and extends a component
base class in a file whose extension cannot compile either. Several modules import through
absolute paths that the TypeScript path configuration does not map. The pipeline invokes a lint
script that the package manifest does not define.

Measured, so the failure is attributable rather than assumed: the frontend image builds through
`COPY package.json`, `npm install` and `COPY . .` and then fails in `npm run build` with
`Module not found: Error: Can't resolve '@paypal/react-paypal-js' in '/app/src'`. That package is
imported by the frontend payment service and declared in no manifest, which is the first of the two
undeclared packages above; declaring it is item 2 in section 4. Type checking reports 18 errors, every
one of them in `frontend/src/services/paypal.ts`, and the output is byte-identical before and after
this work.

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
| The backend base image `python:3.9-slim` is past end of life | The runtime version freeze applies; see section 3.1 |
| Containers run as the root user | Container hardening |

Only the backend base image is named above. `node:22` is in Node.js maintenance support until April
2027, while `python:3.9-slim` tracks Python 3.9, whose upstream support ended in October 2025.
`DL-359` carries the correction to an earlier wording that named both, and `DL-269` carries the
decision to leave the two versions alone.

An eighth observation was closed rather than deferred: the outbound user schema no longer declares the
password hash field. `DL-264` carries that decision.

One further note, recorded rather than acted on: the application exposes interactive API
documentation by default. That is normal for this framework and may well be intentional. Gating it
in production is a one-line change whenever the team decides it should be gated.

### 3.5 The second review's fifteen findings

A security review of the delivered work raised fifteen findings: seven major, six medium and two low.
All fifteen are closed. Each row names what was wrong, what closed it, and what remains, so a finding
closed with a residual is distinguishable from one closed outright.

| # | Severity | What was wrong | What closed it | Residual |
| --- | --- | --- | --- | --- |
| SQ-01 | Major | The charge seam returned false unconditionally, so every subscription was denied, and the route no longer bound the requested plan | The provider-backed verifier was restored: a reference is claimed in a local ledger, resolved through the provider, and bound to state, amount, currency, payer and — for a reusable agreement — the requested plan. A replay is then refused while the reference is retained in the worker-local ledger | The route still cannot persist a row; section 3.3. The ledger holds 4,096 digests per worker, evicts the oldest past that, and is lost on restart, so a replay is refused only while its digest is retained |
| SQ-02 | Major | The listing number validator had lost its finiteness check, so `NaN`, `Infinity` and an overflowing literal were accepted | The finite check and its overflow branch were restored on all three float fields, with no value floor reintroduced | None |
| SQ-03 | Major | The credential scan required no space around the separator, so the formatter-compliant spelling passed | The pattern became whitespace- and quote-aware and gained a lower-case branch, behind a reviewed allow-list; section 2.6 | None |
| SQ-04 | Medium | The suppression staleness check read `PYSEC-` identifiers only, so the GitHub-namespace entry could rot unnoticed | The check now parses `id` and `aliases` from the audit report and fails on any declared identifier absent from both; section 2.4 | None |
| SQ-05 | Major | Both Compose services named a Dockerfile their build context does not contain, build arguments interpolated to empty, the backend received three of eleven required settings, and the port, healthcheck and entry point disagreed | Dockerfile paths corrected, every argument and setting moved to the fail-closed `${VAR:?message}` form, the complete settings contract injected, and the entry point, exposed port, published port and healthcheck reconciled and exercised against a built image | The frontend bundle still does not build; section 3.3 |
| SQ-06 | Major | The filter client mapped over `criteria` as an array while its only caller supplies an object, so the flow failed before any request | An explicit mapper converts the form's value to the wire contract in the service layer, leaving the component and the request contract untouched | None |
| SQ-07 | Major | The client declared a call to `/user/profile`, a route the application never mounts | The dead call was deleted, and a test now compares every path the client declares against the application's own route table | None |
| SQ-08 | Medium | The configuration relied on an ambient Google provider with no version constraint and an untracked lock | A bounded provider range and a bounded command-line range are declared, and the lock is tracked with a directory hash for each of four platforms; section 2.7 | None |
| SQ-09 | Low | Only the package-owned handler folded records, so a root or deployment handler could emit a multiline record | Records are folded at creation by a log-record factory scoped to this application, which runs before propagation | None |
| SQ-10 | Low | The environment file was published by checking the destination and then moving over it, which a directory created after the check absorbs | The publish is a single `link(2)` call that fails when the destination exists in any form, followed by a check that the published path is the regular file the run wrote | None |
| SQ-11 | Medium | This document, the decision log and the traceability matrix carried claims that were stale or stronger than the code | Every documented command was re-run and every count re-measured; the corrections are visible throughout sections 2 and 3 | None |
| SQ-12 | Major | The login throttle keyed on a normalised address while the database lookup was exact, so case-variant accounts shared one counter | The counter is keyed on the stored identity, so counter identity and database identity are the same | Lockout state is in process; section 3.2 |
| SQ-13 | Medium | An unknown address returned before the password hasher ran, which timed the difference between absent and wrong | Both branches perform one fixed-cost verification, against a per-process random stand-in hash when no row exists | Total request timing is not proven equal; the absent branch skips one query (DL-338) |
| SQ-14 | Medium | Only schema `CREATE` was revoked from `PUBLIC`, leaving the database `CONNECT` and `TEMPORARY` privileges every role holds by default | Both are revoked, the effective ACLs are verified by the batch itself, and the cloud instructions carry the same correction; section 3.2 | Schema `USAGE` is deliberately left with `PUBLIC`, and section 3.2 says so |
| SQ-15 | Medium | The database-password variable recommended `-var`, which puts the value in the process arguments and in shell history | The description now requires the environment variable or a gitignored variable file, and mentions the flag only to prohibit it; section 2.7 | None |

---

## 4. Deferred follow-ons, in priority order

1. **Migrate to Python 3.10 or newer, the single highest-priority follow-on.** It is the only real
   remedy for the fifteen advisories in section 3.1, every one of which has a fix release the current
   runtime refuses to install. On completion, empty the suppression list and raise the pins.
2. Generate and commit a frontend lock file after auditing the transitive tree, and declare the two
   packages that are imported but never declared.
3. Move database transport to `verify-full` with a distributed, rotatable root certificate, so the
   connection verifies server identity and not only encryption. Set `DB_SSLMODE=verify-full`, a value
   the settings domain already admits, and give libpq the certificate-authority file path: add
   `sslrootcert` to the `connect_args` in `backend/app/db/database.py`, or export `PGSSLROOTCERT`.
   That engine passes `sslmode` alone today, so the mode without a path falls back to
   `~/.postgresql/root.crt`.
4. Provision a managed secret store with key management, and migrate the deployment pipeline to
   federated identity in place of the long-lived service-account key.
5. Add per-service database roles and row-level security.
6. Authorise a bounded page size on `GET /listings/`, then apply it. The parameters are a frozen
   contract, so the amendment comes first and `DL-187` refuses to narrow them without it. Until then
   one unauthenticated request can read the whole table; section 3.3 carries the residual.
7. Add a full anti-forgery token scheme, replacing reliance on `SameSite=Strict` alone.
8. Add durable, multi-replica-safe account lockout, which needs either migration tooling or an
   external store. The same store closes the two lockout-abuse variants in section 3.2.
9. Add durable, shared replay protection for payment references, so a verified reference is spent
   once across restarts and across replicas rather than inside one worker's bounded ledger. Review
   trigger: the first deployment running more than one worker, or any change to the payment flow.
   Section 3.3 carries the residual.
10. Repair `infrastructure/terraform/outputs.tf` so that plan validation succeeds.
11. Harden the containers: narrow both `COPY . .` instructions to an explicit allow-list, refresh
    both base images, run as a non-root user, pin pipeline actions to immutable digests, and refresh
    the database proxy image.

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
- The database schema. No column was added or altered.

**One item that belongs on no preservation list: the PayPal sandbox checkout experience.** No file in
the frontend payment path was changed, the payment environment moved from a hardcoded literal to a
validated setting whose default is `sandbox`, and the charge seam authorizes a reference the provider
confirms for the requested amount, currency, payer and plan.

What cannot be claimed is that the checkout works end to end, and two measured facts say why. The
frontend bundle does not build: the payment service imports a package no manifest declares, so the
checkout screen cannot be exercised at all. `POST /subscriptions/` cannot persist a row for the schema
reasons in section 3.3, so a provider-confirmed charge clears the gate and then fails at insertion.
Neither is caused by this work, and neither was working beforehand. The accurate statement is that the
checkout path is unchanged and its two pre-existing blockers are unchanged with it.

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
