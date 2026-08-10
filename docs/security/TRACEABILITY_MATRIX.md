# Traceability Matrix

This document is the bidirectional traceability matrix that Rule 1 (Explainability)
requires for a migration or a refactor. This remediation is both: it introduces an
Alembic revision chain where the repository previously had no migration framework, and it
replaces three dependencies — `python-jose` with PyJWT, `passlib` with direct `bcrypt`
calls, and `paypalrestsdk` with REST calls over `httpx`. The Rule's traceability clause
is therefore engaged on two independent grounds, and this file is not discretionary.

The matrix is bidirectional with no gaps, over two populations that must both be
covered for the claim to mean anything: the **20 findings** and the **130 paths this
work delivered**. Its defining property is that completeness can be confirmed
by counting rather than by trusting an assertion, so every total below is stated
explicitly and every total is addable.

### The current baseline, and the four figures to quote

Everything in this file counts against one measurement of one tree. It is stated
here once, restated identically in section 2.10 and in section 7, and quoted nowhere
else in this repository except by the artefacts named in section 5.

| Population | Figure | How it is obtained |
|---|---|---|
| Entries in the plan's transformation mapping | **68** | The frozen Agent Action Plan §0.6.1 publishes it: 30 CREATE, 29 UPDATE, 0 DELETE, 9 REFERENCE |
| Paths this work delivered | **130** | `git diff --name-status a26f7fb HEAD` — 100 created, 30 modified, 0 deleted, with a clean working tree |
| Rows in the reverse index | **156** | `69 + 26 + 61` across sections 4, 4.1 and 4.3 |
| Index rows that are not delivered paths | **26** | 9 read-only reference paths confirmed unmodified, plus 17 paths retired by the manifest consolidation |

`130 + 26 = 156`, and every delivered path is reachable from both axes.

**Figures earlier revisions of this file published, superseded by that measurement and
retained only as history.** Six delivered-path totals were published in succession —
**86**, **91**, **93**, **141**, **125** and **129** — each a correct measurement of the tree that
existed when it was taken, and each left standing beside the next one. A reader
comparing them could not tell which was current, which is the defect. They are
labelled as superseded snapshots where they appear, in section 2.10, and the table
above is the figure to quote. The plan figure was also published twice, as **68** and
as **69**; **68** is correct, because it is the total the frozen plan itself states,
and section 2.8 records what the other count was counting.

**What an earlier version of this file got wrong, recorded rather than quietly
corrected.** It asserted 100% coverage while enumerating only the entries the plan
foresaw. That is not the same population: most of the delivered paths are outside the
plan's mapping, so a matrix covering the plan alone left changed paths traceable
from neither direction — and the assertion of completeness made that harder to notice,
not easier. The same version recorded `infrastructure/docker/Dockerfile.frontend` as a
read-only path "confirmed unmodified", which a diff disproves. Section 2.9 now carries
the delivered-beyond-plan paths in both directions, section 2.7 states that path's
real mode, and section 5 counts the whole delivered population.
`docs/security/DECISION_LOG.md` §35.27.2 holds the reasoning for the reference-path
correction, and row 91.4 the decision to publish one inventory and where.

## Totals — reconciliation against the plan

| Quantity | Figure |
|---|---|
| Findings mapped | **20** — C-1 to C-4, H-1 to H-7, M-1 to M-4, INFRA-1 to INFRA-5 |
| Entries in the plan's transformation mapping | **68** |
| — of those, CREATE | **30** |
| — of those, UPDATE | **29** |
| — of those, DELETE | **0** |
| — of those, REFERENCE | **9** — section 2.7's table, which is the set the plan's own total counts |
| Planned changed paths delivered | **59 of 59**, none pending |
| Paths delivered beyond the plan's mapping | **87** — sections 2.9 and 6 |
| **Delivered paths in total** | **130** — 100 created, 30 modified, 0 deleted |
| — of those, created | **100** |
| — of those, modified | **30** |
| Rows in the reverse index | **156** — sections 4, 4.1 and 4.3 |
| Index rows that are not delivered paths | **26** — 9 read-only references confirmed unmodified, 17 retired by the manifest consolidation |
| Dependency advisories | **19 across 7 packages** before, **7 across 3** after |
| Static-analysis findings at Medium or above | **1** before, **0** after |
| Role-matrix assertions | **45** — 9 routes across 5 principals |
| Accounts holding the administrative role after migration | exactly **1** |
| Tables in the delivered schema | **8**, plus 1 bookkeeping table a revision owns |
| Columns | **48** — 33 `NOT NULL`, 15 nullable |
| — of those, added by this work | **14** — 7 appended to pre-existing tables, each with a server default, 4 with the table `0001` creates and 3 with the table `0005` creates |
| Server defaults | **10** |
| Primary keys | **8** |
| Foreign keys | **4** |
| Uniqueness constraints | **3** — 1 column-level, 2 named — plus **1** partial unique index, section 5.4 |
| ORM relationships | **8**, forming 4 reciprocal pairs |
| Indexes | **7** — 6 non-unique from `0003`, 1 partial unique from `0004` |

`30 + 29 + 0 + 9 = 68` for the plan, and `59 + 27 + 61 - 17 = 130` for the delivered tree,
stated in full in sections 2.10 and 6.1. The index adds the paths the tree no longer
carries and the references it never changed: `130 + 9 + 17 = 156`.

## Where this document sits among its siblings

Four documents carry this remediation's written record, and each answers a different
question. This matrix **maps**: it connects each finding to the files that remediate it
and the tests that verify it. `docs/security/DECISION_LOG.md` **argues**: it holds the
reasoning, the alternatives and the risks. `docs/security/RESIDUAL_RISK.md`
**evidences**: it carries the advisories accepted under the runtime pin and the
measurement behind each compensating control. `docs/security/CREDENTIAL_ROTATION.md`
**sequences**: it orders the operational steps for the exposed credentials.

No rationale appears in this file. Rule 1 makes the decision log the single source of
truth for *why*, so where a mapping rested on a judgement call this matrix names the
mapping and cross-references `docs/security/DECISION_LOG.md` rather than re-arguing it.
None of the tables below carries a "why" column, by design.

## How bidirectionality is achieved

Axis 1 runs forward from each finding to the files that fix it and the tests that prove
it; Axis 2 runs from each replaced construct to the construct that replaced it; Axis 3
runs from each schema construct to the revision operation that produces it; and the
reverse index in section 4 runs backward from each target file to the finding it serves
and the test that covers it. Every finding, every target file and every schema construct
is therefore reachable from both directions, which is what the Rule's word
"bidirectional" requires and what a one-way listing would not satisfy.

Axis 3 exists because the other two map the two Alembic revisions at file level, which is
the right granularity for a finding-to-file axis and too coarse for a schema: it cannot
show that every construct the models declare is produced by a revision, nor that every
construct a revision produces is declared by the models. Section 5 answers both, per
table, column, type, nullability, default, key and constraint, with its own reverse index
in section 5.7.

## Two conventions this file follows

**Line numbers locate the baseline tree.** Every line number cited below resolves against
revision `a26f7fb`, the last revision before this remediation began. Most of the files
named here have since been rewritten, so a baseline line number will not resolve against
the current tree — `@asyncio.coroutine` at `backend/app/tasks/listing_updater.py:10` is
one of several. Baseline numbers are kept because they are what the findings and the plan
cite. This is the same convention `docs/security/DECISION_LOG.md` adopts, and every
location in section 3 was read back from that revision rather than copied from a summary.

**The figure 68 counts plan entries, not changed files.** It is 59 planned changes — the
30 CREATE and 29 UPDATE entries — plus the 9 REFERENCE paths, 8 of which are read and never
modified and 1 of which was modified after all and is reconciled in section 6.3. The two
quantities are not interchangeable, and this matrix does not present 68 as a count of
changed files. **Section 2.10 of this file is the authority for the planned-versus-actual
reconciliation**, and it supersedes every earlier figure: the per-round snapshots at
`docs/security/DECISION_LOG.md` §23.1 and §85.1, which recorded 58 changed paths with 12
pending and projected 70, and this file's own earlier totals of 86 and 141. Those figures
were accurate for the rounds that measured them; section 2.10 is the whole of the work,
and `docs/security/DECISION_LOG.md` row 91.4 carries the decision behind it.

---

## 1. Axis 1 — finding to target file to verifying test

All 20 findings, in the order the plan's finding register assigns them. No cell is empty.

| Finding | Weakness | Severity | Baseline location | Remediating target file | Verifying test or command |
|---|---|---|---|---|---|
| **C-1** | Weak or placeholder signing key accepted at startup | Critical | `scripts/setup_dev_environment.sh:54` writes the placeholder `your_secret_key_here`; `backend/app/core/config.py:6` accepts any string, and `:4-12` declares eight settings with no validator of any kind | `backend/app/core/config.py`, `scripts/setup_dev_environment.sh`, `.env.example` | `backend/tests/security/test_config_validation.py`; the script side additionally by `backend/tests/security/test_setup_script.py` and `backend/tests/security/test_setup_script_bootstrap.py` |
| **C-2** | Signing and verification algorithm read from unvalidated configuration | Critical | `backend/app/core/security.py:27` signs and `:34` verifies with the single unvalidated string declared at `backend/app/core/config.py:7` | `backend/app/core/config.py`, `backend/app/core/security.py` | `backend/tests/security/test_config_validation.py`, `backend/tests/security/test_jwt_hardening.py` |
| **C-3** | PayPal mode hardcoded to `sandbox`, with a source comment as its only production control | Critical | `backend/app/services/paypal_service.py:11` | `backend/app/services/paypal_service.py`, `backend/app/core/config.py` | `backend/tests/security/test_config_validation.py` |
| **C-4** | Database credentials and a cloud service-account key committed; no `.gitignore` existed at any level | Critical | `infrastructure/docker/docker-compose.yml:30` and `:46-49`, cited by path and line only | `.gitignore`, `.dockerignore`, `.env.example`, `infrastructure/docker/docker-compose.yml`, `infrastructure/terraform/main.tf`, `docs/security/CREDENTIAL_ROTATION.md` | `git check-ignore` over the newly ignored paths, and `backend/tests/security/test_deployment_contract.py`; the rotation itself is verified manually against `docs/security/CREDENTIAL_ROTATION.md` |
| **H-1** | No role-based access control, and no `role` column on `User` | High | `backend/app/db/models.py:7-17`; every protected route depends on `get_current_user` alone, at `listings.py:18`, `filters.py:12` and `:31`, and `subscriptions.py:17` and `:49` | `backend/app/db/models.py`, `backend/app/core/authorization.py`, `backend/migrations/versions/0001_add_rbac_and_subscription_columns.py`, `backend/migrations/versions/0002_seed_single_admin.py`, and all four endpoint modules | `backend/tests/security/test_rbac_matrix.py`, whose grid is 9 routes across 5 principals for 45 assertions |
| **H-2** | Client controls the charge amount and the entitlement dates | High | `backend/app/api/endpoints/subscriptions.py:24` passes a client amount; `:32-33` persist client dates | `backend/app/api/endpoints/subscriptions.py`, `backend/app/core/plans.py`, `backend/app/schema/subscription.py` | `backend/tests/security/test_subscription_tampering.py`, its `test_h2_*` cases |
| **H-3** | Insecure direct object reference on payment capture | High | `backend/app/services/paypal_service.py:41-47`, where both identifiers arrive from the caller and no lookup binds either to a user | `backend/app/services/paypal_service.py`, `backend/app/api/endpoints/subscriptions.py`, `backend/app/db/models.py` | `backend/tests/security/test_subscription_tampering.py`, its `test_h3_*` cases |
| **H-4** | No PayPal webhook signature verification anywhere in the codebase | High | Absence throughout `backend/app/services/paypal_service.py`: no verification function, no webhook route and no stored webhook identifier existed | `backend/app/services/paypal_service.py`, `backend/app/api/endpoints/subscriptions.py`, `backend/app/db/models.py` | `backend/tests/security/test_paypal_webhook.py` |
| **H-5** | Unbounded pagination on the public listings endpoint | High | `backend/app/api/endpoints/listings.py:13`, where the page-size parameter carries a default and no maximum | `backend/app/api/endpoints/listings.py`, `backend/app/core/config.py` | `backend/tests/security/test_request_bounds_and_refusals.py`, its page-size and offset cap cases; continued public reachability by `backend/tests/security/test_rbac_matrix.py` |
| **H-6** | Mass assignment from the request body into the ORM model | High | `backend/app/api/endpoints/listings.py:23`, which unpacks the request body and also passes an `owner_id` that `backend/app/db/models.py` never declares | `backend/app/api/endpoints/listings.py`, `backend/app/schema/listing.py` | `backend/tests/security/test_mass_assignment.py` |
| **H-7** | Token `sub` claim carries an email but is compared against an integer primary key | High | Minted as an email at `backend/app/api/endpoints/auth.py:25` and `:45`; read at `backend/app/core/security.py:35`; compared against an integer column at `:48` | `backend/app/core/security.py`, `backend/app/api/endpoints/auth.py` | `backend/tests/security/test_jwt_hardening.py`; additional forgery coverage in `backend/tests/security/test_token_hardening.py` |
| **M-1** | User-enumeration oracles: a distinct 404 for a missing user, and a short-circuited credential check | Medium | `backend/app/core/security.py:50` returns 404 where an invalid token returns 401; `backend/app/api/endpoints/auth.py:41` short-circuits so the hash comparison runs only for an existing account | `backend/app/core/security.py`, `backend/app/api/endpoints/auth.py` | `backend/tests/security/test_jwt_hardening.py`, `backend/tests/security/test_login_lockout_and_rate_limit.py`; timing equalisation in `backend/tests/security/test_login_throttling_and_timing.py` |
| **M-2** | No security-headers middleware | Medium | Absence in `backend/app/main.py`, whose middleware stack at `:23-29` adds cross-origin handling alone | `backend/app/main.py` | `backend/tests/security/test_application_surface.py`, its `test_the_security_headers_are_still_set` and `test_the_refusal_carries_the_protective_headers` cases |
| **M-3** | Wildcard CORS methods and headers combined with `allow_credentials=True` | Medium | `backend/app/main.py:23-29`, specifically credentialed requests at `:26` alongside wildcard methods at `:27` and wildcard headers at `:28` | `backend/app/main.py`, `backend/app/core/config.py` | `backend/tests/security/test_settings_and_redaction.py`, its `test_explicit_origins_are_accepted` and `test_wildcard_and_empty_origins_are_rejected` cases |
| **M-4** | Secrets reachable through logs, and the Zillow key carried in URL query parameters | Medium | `backend/app/services/zillow_service.py:15-19` places the key in the query dictionary and `:27` prints exception text that embeds the full keyed URL; `backend/app/services/email_service.py:22` and `backend/app/tasks/listing_updater.py:29` print likewise | `backend/app/services/zillow_service.py`, `backend/app/services/email_service.py`, `backend/app/tasks/listing_updater.py`, `backend/app/core/logging.py` | `backend/tests/test_services.py`; redaction coverage in `backend/tests/security/test_settings_and_redaction.py`, including `test_credential_never_reaches_the_stream` |
| **INFRA-1** | Terraform provisions no Secret Manager resources at all; Cloud SQL has no private IP, no SSL requirement and no backups; the GKE control plane is public and nodes run on the default compute service account; the HTTP function has no invoker restriction | High | `infrastructure/terraform/main.tf:10-106`, including `:58` where `deletion_protection = false` | `infrastructure/terraform/main.tf`, `infrastructure/terraform/variables.tf`, `infrastructure/terraform/outputs.tf` | `terraform validate`, which fails at baseline because the outputs file references resources that do not exist. The function runtime pin at `:99` is deliberately left unchanged |
| **INFRA-2** | CI and CD carry no `permissions` block, no dependency or SAST gate, and authenticate with a long-lived service-account key | High | `.github/workflows/ci.yml` declares no `permissions` and at `:44` invokes a linter it never installs; `.github/workflows/cd.yml:26` supplies a long-lived key | `.github/workflows/ci.yml`, `.github/workflows/cd.yml` | The CI gates themselves: `pip-audit -r backend/requirements.txt`, `bandit -r backend/app -ll`, the security suite, and the two compensating-control guards. The interpreter pin `python-version: '3.9'` in `ci.yml` is deliberately left unchanged |
| **INFRA-3** | The backend image runs as root and copies the whole tree with no `.dockerignore`, so any local environment file or secrets directory is baked into the image | Medium | `infrastructure/docker/Dockerfile.backend:14` copies the tree unfiltered and the file declares no `USER`; `:8` copies a manifest that did not exist, so the build failed before any security consideration | `infrastructure/docker/Dockerfile.backend`, `.dockerignore` | The container build verification, plus `backend/tests/security/test_deployment_contract.py`. The base image tag at `:2` is deliberately left unchanged |
| **INFRA-4** | The deployment script has no failure handling, authenticates from an on-disk key file, and deploys the Cloud Function with `--allow-unauthenticated` | High | `scripts/deploy.sh:1` sets no shell failure options, `:5` activates a service account from a key file, and `:24` passes the unauthenticated-invocation flag | `scripts/deploy.sh` | `bash -n scripts/deploy.sh`, and `backend/tests/security/test_pipeline_contract.py`, whose script cases assert strict shell failure options, the absence of `--allow-unauthenticated`, the absence of on-disk key activation, the registry host, that credentials and namespace are asserted before any mutation, and that migrations run before the rollout. An earlier revision of this matrix recorded that no automated coverage targeted this file; that is superseded. The runtime pin is deliberately left unchanged |
| **INFRA-5** | No Python dependency manifest exists anywhere in the repository, so the running dependency set is unversioned and uninventoried | High | Absence under `backend/`: no `requirements.txt`, `Pipfile`, `pyproject.toml` or lock file, while `infrastructure/docker/Dockerfile.backend:8` copies one | `backend/requirements.txt`, `backend/requirements-dev.txt` | `pip-audit -r backend/requirements.txt` and `pip-audit -r backend/requirements-dev.txt`, invoked against the manifest rather than the environment |

**Distinct findings in this table: 20.** No identifier is duplicated and none is invented.

---

## 2. Axis 1 continued — the plan's 68 transformation entries

The same forward direction, enumerated by target path so that every entry in the plan's
transformation mapping is accounted for. Groups follow the plan's own grouping. Each row
names the path, the transformation mode, and the finding it serves. Rows whose authority
is a Rule rather than a finding name the Rule, so that no cell is left empty.

The tables below render **69** rows for those 68 entries. The extra row is
`backend/app/api/router.py`, and section 2.8 states why it is rendered here and not
counted a second time.

### 2.1 Application core and endpoints

| Target path | Mode | Serves |
|---|---|---|
| `backend/app/core/config.py` | UPDATE | C-1, C-2, C-3, H-5, M-3 |
| `backend/app/core/security.py` | UPDATE | C-2, H-7, M-1 |
| `backend/app/core/authorization.py` | CREATE | H-1 |
| `backend/app/core/logging.py` | CREATE | M-4 |
| `backend/app/core/plans.py` | CREATE | H-2 |
| `backend/app/main.py` | UPDATE | M-2, M-3 |
| `backend/app/api/endpoints/auth.py` | UPDATE | H-7, M-1 |
| `backend/app/api/endpoints/listings.py` | UPDATE | H-1, H-5, H-6 |
| `backend/app/api/endpoints/filters.py` | UPDATE | H-1 |
| `backend/app/api/endpoints/subscriptions.py` | UPDATE | H-1, H-2, H-3, H-4 |
| `backend/app/api/router.py` | REFERENCE — contextual, counted in no total; see section 2.8 | H-4, as negative evidence: the new webhook route mounts under the existing `/subscriptions` prefix, so this file needs no edit, which is what demonstrates the four-prefix constraint is honoured |

Counted subtotal: 3 CREATE + 7 UPDATE = **10**. The eleventh row,
`backend/app/api/router.py`, is contextual evidence and is counted in no total;
section 2.8 states that partition.

### 2.2 Services, tasks, models and schemas

| Target path | Mode | Serves |
|---|---|---|
| `backend/app/services/paypal_service.py` | UPDATE | C-3, H-3, H-4 |
| `backend/app/services/zillow_service.py` | UPDATE | M-4 |
| `backend/app/services/email_service.py` | UPDATE | M-4 |
| `backend/app/tasks/listing_updater.py` | UPDATE | M-4 |
| `backend/app/db/models.py` | UPDATE | H-1, H-3, H-4 |
| `backend/app/db/database.py` | UPDATE | H-1, as a precondition: the entrypoint imports a symbol this module never exported, so nothing could be verified until it did |
| `backend/app/schema/user.py` | UPDATE | C-1, H-7 |
| `backend/app/schema/listing.py` | UPDATE | H-6 |
| `backend/app/schema/filter.py` | UPDATE | H-6 |
| `backend/app/schema/subscription.py` | CREATE | H-2 |

Counted subtotal: 1 CREATE + 9 UPDATE = **10**.

### 2.3 Migrations and dependency manifests

| Target path | Mode | Serves |
|---|---|---|
| `backend/requirements.txt` | CREATE | INFRA-5 |
| `backend/requirements-dev.txt` | CREATE | INFRA-5 |
| `backend/alembic.ini` | CREATE | H-1 |
| `backend/migrations/env.py` | CREATE | H-1 |
| `backend/migrations/script.py.mako` | CREATE | H-1 |
| `backend/migrations/versions/0001_add_rbac_and_subscription_columns.py` | CREATE | H-1, H-3, H-4 |
| `backend/migrations/versions/0002_seed_single_admin.py` | CREATE | H-1 |

Counted subtotal: 7 CREATE = **7**.

### 2.4 Test suite

| Target path | Mode | Serves |
|---|---|---|
| `backend/tests/conftest.py` | CREATE | Fixtures for C-1 to INFRA-5, and the one file that makes the suite collect from `backend/` as well as from the repository root |
| `backend/tests/security/__init__.py` | CREATE | Package marker for the security suite |
| `backend/tests/security/test_jwt_hardening.py` | CREATE | C-2, H-7, M-1 |
| `backend/tests/security/test_rbac_matrix.py` | CREATE | H-1, H-5 |
| `backend/tests/security/test_subscription_tampering.py` | CREATE | H-2, H-3 |
| `backend/tests/security/test_paypal_webhook.py` | CREATE | H-4 |
| `backend/tests/security/test_mass_assignment.py` | CREATE | H-1, H-6 |
| `backend/tests/security/test_config_validation.py` | CREATE | C-1, C-2, C-3 |
| `backend/tests/security/test_login_lockout_and_rate_limit.py` | CREATE | M-1 |
| `backend/tests/test_api.py` | UPDATE | Regression cover for H-1, H-5, M-3 and the frozen login response shape |
| `backend/tests/test_services.py` | UPDATE | M-4 |
| `backend/tests/test_tasks.py` | UPDATE | M-4 |

Counted subtotal: 9 CREATE + 3 UPDATE = **12**.

The nine CREATE entries above are the security suite the plan enumerates. Seven are
`test_*.py` modules under `backend/tests/security/`; the eighth is that folder's package
marker; and `backend/tests/conftest.py` sits at `backend/tests/` rather than under
`security/`. Modules delivered beyond this enumerated set are enumerated in section 6.2 by
path and in section 6.4 by the finding each serves, and are additive: several appear in the
verifying-test column of section 1 because they hold the closest coverage of a finding, and
each is attributed there by path. `docs/security/DECISION_LOG.md` §23.2 carries the reasoning
for adding them.

**What `conftest.py` fixes, stated narrowly, because an earlier revision of this file
overstated it.** The baseline suite reported `no tests collected, 3 errors` — and the
cause of that was the eight **import-time faults** in the application package, chief
among them the request models the endpoint modules imported and the `Base` symbol
imported from a module that never exported it. Those faults are traced to
`backend/app/schema/*.py` and `backend/app/db/database.py` in section 1, not here.
What `conftest.py` fixes is a **narrower and separate** problem: the pipeline's own
invocation runs `cd backend` before `pytest`, which leaves the repository root off
`sys.path`, and every module in the suite imports absolute `backend.app.*` paths. All
ten modules failed to collect under that invocation with `ModuleNotFoundError: No
module named 'backend'`. `conftest.py` is the only file pytest is guaranteed to import
before any test module, so it is where the repository root is prepended and where the
settings a working-directory-independent run needs are supplied. The rationale is
recorded at `docs/security/DECISION_LOG.md` rows 11.2 and 17.1; row 35.2 records this
correction.

### 2.5 Infrastructure, pipelines and scripts

| Target path | Mode | Serves |
|---|---|---|
| `.gitignore` | CREATE | C-4 |
| `.dockerignore` | CREATE | C-4, INFRA-3 |
| `.env.example` | CREATE | C-1, C-4 |
| `infrastructure/docker/docker-compose.yml` | UPDATE | C-1, C-4 |
| `infrastructure/docker/Dockerfile.backend` | UPDATE | INFRA-3, INFRA-5 |
| `infrastructure/terraform/main.tf` | UPDATE | C-4, INFRA-1 |
| `infrastructure/terraform/variables.tf` | UPDATE | INFRA-1 |
| `infrastructure/terraform/outputs.tf` | UPDATE | INFRA-1 |
| `.github/workflows/ci.yml` | UPDATE | INFRA-2 |
| `.github/workflows/cd.yml` | UPDATE | INFRA-2, C-4 |
| `scripts/deploy.sh` | UPDATE | INFRA-4 |
| `scripts/setup_dev_environment.sh` | UPDATE | C-1, C-4 |

Counted subtotal: 3 CREATE + 9 UPDATE = **12**.

### 2.6 Documentation and rule-mandated deliverables

| Target path | Mode | Serves |
|---|---|---|
| `docs/security/DECISION_LOG.md` | CREATE | Rule 1 (Explainability) — the decision-log clause |
| `docs/security/TRACEABILITY_MATRIX.md` | CREATE | Rule 1 (Explainability) — the bidirectional-matrix clause; this file |
| `docs/security/RESIDUAL_RISK.md` | CREATE | The accepted-residual-risk instruction, for the 7 advisories with no reachable fix under the runtime pin |
| `docs/security/CREDENTIAL_ROTATION.md` | CREATE | C-4 — the rotation sequencing the finding requires and no code change can deliver |
| `docs/review/CRITICAL_DECISIONS.md` | CREATE | Rule 3 (Critical Decision Review Document), at the literal path that Rule names |
| `blitzy-deck/executive-summary.html` | CREATE | Rule 2 (Executive Presentation) |
| `SECURITY.md` | CREATE | Vulnerability disclosure policy and supported-version statement |
| `README.md` | UPDATE | C-1, C-4, and notice of the one intentional breaking change |

Counted subtotal: 7 CREATE + 1 UPDATE = **8**.

**All eight entries above are delivered.** Every path was read back from the working
tree at the close of the change set, and the mode column states the delivered mode
rather than an intent:

| Target path | Delivered mode | Delivered state read back from the tree |
|---|---|---|
| `docs/security/DECISION_LOG.md` | CREATE | Present. Sections 1 to 44 and 79 to 89, the 45-to-78 band having been removed as a duplicate re-issue; §89 is the final-state reconciliation |
| `docs/security/TRACEABILITY_MATRIX.md` | CREATE | Present — this file |
| `docs/security/RESIDUAL_RISK.md` | CREATE | Present. Two registers: seven accepted advisories in the packages the deployed image installs, with a one-to-one ledger over the nineteen, and seven more in the verification tooling |
| `docs/security/CREDENTIAL_ROTATION.md` | CREATE | Present. Staged runbook: provision, deploy and verify, then rotate |
| `docs/review/CRITICAL_DECISIONS.md` | CREATE | Present, at the literal path Rule 3 names. Five risk-ordered decisions with reviewer personas and checks |
| `blitzy-deck/executive-summary.html` | CREATE | Present. Single self-contained reveal.js file |
| `SECURITY.md` | CREATE | Present. Disclosure policy and supported-version statement |
| `README.md` | UPDATE | Present. Carries the Security and Setup section and the breaking-change notice |

**All eight rows above are delivered.** An earlier revision of this section recorded
five of those paths as absent — `docs/security/RESIDUAL_RISK.md`,
`docs/security/CREDENTIAL_ROTATION.md`, `docs/review/CRITICAL_DECISIONS.md`,
`blitzy-deck/executive-summary.html` and `SECURITY.md` — because five were still owned by
later checkpoints when this file was first written. That was true then and is false now,
and the record of it stays visible rather than being quietly overwritten:
`docs/security/DECISION_LOG.md` rows 26.19, 29.11, 30.15, 32.12 and 33.11 hold the
position as each round took it, **row 35.1.1** withdraws all five, and **row 35.1**
reconciles them against this delivered state. Cite rows 35.1 and 35.1.1 for what is true
today and the five earlier rows for the chronology. The mode column states both the plan's
intent and the delivered state, because they agree.

An earlier revision of this section stated the same correction twice, in two paragraphs
that named four withdrawn rows in one and five in the other. One paragraph naming all five
replaces both.

### 2.7 Read-only references

Nine paths the plan marks read-only. Eight were read to constrain the design and never
modified. One — `infrastructure/docker/Dockerfile.frontend` — was modified during the work
and is reconciled in section 6.3; the Mode column below records the plan's mode, so the
count in section 2.8 is unaffected.

| Target path | Mode | Serves |
|---|---|---|
| `frontend/src/services/auth.ts` | REFERENCE | H-7 — establishes the token-storage contract, which forecloses moving the token into a cookie |
| `frontend/src/services/paypal.ts` | REFERENCE | H-2 — confirms no client sends an amount. **It does not evidence the hosted redirect:** it drives the provider's Billing Subscriptions product through `actions.subscription.create()` and never reads the backend's `approval_url`, which is the product mismatch registered as O-6 and logged at `DECISION_LOG.md` row 80.6.3. The redirect is evidenced by `backend/app/schema/subscription.py`, `backend/app/api/endpoints/subscriptions.py` and `backend/app/services/paypal_service.py`, whose rows carry it in sections 2.1, 2.2 and 4 |
| `frontend/src/schema/subscription.ts` | REFERENCE | H-2 — the response shape the backend must keep satisfying; it carries no amount field |
| `frontend/src/utils/validators.ts` | REFERENCE | C-1 — the documented password policy the new server-side guard realizes |
| `frontend/package.json` | REFERENCE | INFRA-2 — confirms the lock-file assumption the pipeline makes |
| `infrastructure/docker/Dockerfile.frontend` | REFERENCE in the plan; delivered as UPDATE, see section 6.3 | INFRA-3 — confirms the same lock-file assumption. Two `ARG` declarations were added so the non-secret build arguments reach the bundle |
| `documentation/Technical Specifications.md` | REFERENCE | H-1 — design-intent authority for the four roles and the absent secret management |
| `documentation/Software Requirements Specifications (SRS).md` | REFERENCE | M-1 — design-intent authority for the lockout parameters and the password policy |
| `documentation/Software Project Proposal.md` | REFERENCE | INFRA-2 — design-intent authority for the coverage targets |

Counted subtotal: 9 REFERENCE = **9**. Unmodified in delivery: **8**. Modified in
delivery: **1** — `infrastructure/docker/Dockerfile.frontend`.

**Correction — one reference-mode path was modified in delivery.** This section
and the reverse index of section 4 both previously recorded every one of these
nine paths as "Confirmed unmodified; absent from the changed set". That was true
of eight and false of `infrastructure/docker/Dockerfile.frontend`, which commit
`25b378b` changed with nine insertions: two `ARG` declarations, their paired
`ENV` exports, and the four comment lines that explain why a Create React App
build needs both. `git log --follow` on the path reports the commit, and
`docs/security/DECISION_LOG.md` row 30.12 records the decision behind it. The
claim was therefore contradicted by the tree at the moment it was written, and
Rule 1 makes a document that a reader can disprove a defect rather than an
approximation — so the row above and the row in section 4 are corrected instead
of being left to be discovered.

Three consequences follow, and each is stated so that no count in this document
has to be re-derived:

- **The mode subtotals are unchanged, deliberately.** Section 2 enumerates *the
  plan's* 68 entries, and the plan assigns this path REFERENCE mode. The subtotal
  stays at 9 because it counts planned modes, not delivered operations; changing
  it would misreport the plan, which is frozen. What changed is the delivery, and
  the row now carries both facts.
- **Delivery touched 60 of the plan's own paths, not 59.** The 59 figure is the plan's
  CREATE plus UPDATE columns. One reference-mode path having been modified means
  delivery touched one more path than the plan's changed set contains, which is the
  `59 + 1` of section 2.10's first table. Row 35.9.4 of
  `docs/security/DECISION_LOG.md` withdraws that document's §23.1 sentence asserting
  all nine remain unmodified, for the same reason this correction exists.
- **Eight of these nine paths, not all nine, are verifiable by absence.** The
  completeness statement in section 7 states which they are, so "absent from the
  changed set" is claimed only where it is true. Counting the contextual row section
  2.1 carries, `backend/app/api/router.py`, nine paths in total are verifiable that
  way; section 2.8 states that partition.

### 2.8 Entry count reconciliation

| Group | CREATE | UPDATE | DELETE | REFERENCE | Subtotal |
|---|---|---|---|---|---|
| 2.1 Application core and endpoints | 3 | 7 | 0 | 0 | 10 |
| 2.2 Services, tasks, models and schemas | 1 | 9 | 0 | 0 | 10 |
| 2.3 Migrations and dependency manifests | 7 | 0 | 0 | 0 | 7 |
| 2.4 Test suite | 9 | 3 | 0 | 0 | 12 |
| 2.5 Infrastructure, pipelines and scripts | 3 | 9 | 0 | 0 | 12 |
| 2.6 Documentation and rule-mandated deliverables | 7 | 1 | 0 | 0 | 8 |
| 2.7 Read-only references | 0 | 0 | 0 | 9 | 9 |
| **Total** | **30** | **29** | **0** | **9** | **68** |

`30 + 29 + 0 + 9 = 68`, and the CREATE and UPDATE columns alone give the
`30 + 29 = 59` planned changed paths that section 6.1 reconciles against the tree,
all 59 delivered.

Two properties of this count are worth stating so a reviewer can reproduce it rather than
re-derive it.

**`backend/app/api/router.py` is rendered in section 2.1 and is not added to this total.**
The frozen Agent Action Plan §0.6.1 publishes its own totals — 30 CREATE, 29 UPDATE, 0
DELETE, 9 REFERENCE, 68 entries — and its nine reference entries are the table at §0.6.1.7.
The router module is the one reference-mode row the plan renders inside its
application-core group instead, so counting it here would give a reference column of 10
and a total of 69 that the plan itself does not publish. This table reproduces the plan's
figures. Section 2.1 still carries the row and the reverse index still carries the path,
because a file needing no edit is what proves the four router prefixes were preserved, so
it stays reachable from both directions without being counted. An earlier revision of this
file counted it and published 69; that count is superseded, and **68** is the figure every
sibling artefact quotes.

**The DELETE column is 0, and that is a finding about the repository rather than an
omission here.** No file in this repository existed solely to introduce a vulnerability,
so the mode had no legitimate target; `docs/security/DECISION_LOG.md` §34.7.1 records the
position, including why two unplanned byproduct files removed during the work leave this
column at 0. A later round did remove seventeen paths it had itself created, which is a
delivered operation rather than a plan entry: section 2.9 carries them with DELETE in the
Mode column and section 2.10 counts them apart from the delivered total.

### 2.9 Paths delivered beyond the plan's mapping

Sections 2.1 to 2.8 enumerate the plan. This section enumerates what was delivered and the
plan does not contain, so that the forward axis covers the tree rather than only the
intention. None of these paths is counted among the 68; each is additive, and each is
listed with the finding or authority it serves and the decision-log row that admits it.

**87 rows, in two tables.** 70 of them are paths the delivered tree carries, and those 70
are the third term of section 2.10's delivered total. The other 17 are paths a round of
this work created and a later round removed: 16 retired when the Kubernetes inventory was
consolidated onto one directory, and 1 whose creation was reverted. Each of the 17 carries
DELETE or a withdrawal in its Mode column, so a row is never read as a claim that the path
is present. `docs/security/DECISION_LOG.md` §23.2 enumerated 11 of these when it was
written; that figure is superseded by section 2.10, which is the only place a delivered
total is published.

| Target path | Mode | Serves | Decision-log row |
|---|---|---|---|
| `backend/app/core/rate_limit.py` | CREATE | H-5, and the bounded credential-endpoint throttle the plan requires without naming a module for it | §23.2.2, and §23.3.1 for the direct `limits` pin it forces |
| `backend/.dockerignore` | CREATE | C-4, INFRA-3 — the plan names only the repository-root file, and the documented build uses `backend/` as its context | §23.2.1 |
| `frontend/.dockerignore` | CREATE | C-4, INFRA-3 — the same reasoning for the frontend context | §32, container-contents round |
| `frontend/package-lock.json` | CREATE | INFRA-2 — required by `npm ci` in both the frontend image and the pipeline; produced by environment setup rather than by this work | §23.2.3 |
| `setup.cfg` | CREATE | Rule 1, and the gate definitions `flake8` and `pytest` read — the coverage floor, the strict asynchronous mode and the two frozen `router.py` ignores | §35.1.1 |
| `infrastructure/terraform/.terraform.lock.hcl` | CREATE, **withdrawn — absent from the tree** | INFRA-1 — it recorded resolved provider hashes for a provider version constraint that the same revert removed, so nothing remains for it to lock | §36.3.1 for the original decision; row 91.1.1 for the revert that removed both |
| `backend/tests/support.py` | CREATE | Rule 1 — one module object holding the shared test values, which is what keeps `conftest.py` from being imported twice | §27.6 |
| `backend/tests/security/test_token_hardening.py` | CREATE | Verifies C-2, H-7 — token forgery beyond the planned module | §23.2.4 |
| `backend/tests/security/test_authorization.py` | CREATE | Verifies H-1 at unit level, which the route-driven matrix reaches only indirectly | §23.2.5 |
| `backend/tests/security/test_payment_lifecycle.py` | CREATE | Verifies C-3, H-3, H-4 — order, capture and settlement across the rewritten provider client | §23.2.6 |
| `backend/tests/security/test_login_throttling_and_timing.py` | CREATE | Verifies M-1 — timing equalisation and limiter behaviour | §23.2.7 |
| `backend/tests/security/test_request_bounds_and_refusals.py` | CREATE | Verifies H-5, H-6 — body cap, pagination bounds and refusal shape | §23.2.8 |
| `backend/tests/security/test_settings_and_redaction.py` | CREATE | Verifies C-1, C-2, C-3, M-3, M-4 — validators and log redaction | §23.2.9 |
| `backend/tests/security/test_application_surface.py` | CREATE | Verifies M-2, M-3 — route inventory, headers, CORS, health endpoints and fail-closed route matching | §23.2.10, and §36.5.1 for the route-matching cases |
| `backend/tests/security/test_migrations.py` | CREATE | Verifies H-1 — executes every revision in the chain, proving the additive defaults, idempotence, reversibility and sole-admin post-condition | §23.2.11 |
| `backend/tests/security/test_migration_gate.py` | CREATE | Verifies H-1 — that the schema is owned by migrations rather than created at import | §26 |
| `backend/tests/security/test_migration_revisions.py` | CREATE | Verifies H-1, H-3, H-4 — the DDL each revision applies | §25 |
| `backend/tests/security/test_revision_contracts.py` | CREATE | Verifies H-1 — the revision template and the chain's identifiers | §26 |
| `backend/tests/security/test_admin_seed_migration.py` | CREATE | Verifies H-1 — the single-administrator grant and its post-condition | §25 |
| `backend/tests/security/test_rate_limit_store.py` | CREATE | Verifies H-5 — the bounded key ceiling of the in-process store | §26 |
| `backend/tests/security/test_setup_script.py` | CREATE | Verifies C-1, C-4 — that the setup script writes no placeholder key and no credentialed connection string | §28 |
| `backend/tests/security/test_setup_script_bootstrap.py` | CREATE | Verifies C-1, C-4 — the bootstrap path the script takes and the values it generates | §29 |
| `backend/tests/security/test_deployment_contract.py` | CREATE | Verifies C-1, C-4, INFRA-3 — the container stack, the two Dockerfiles and `.env.example` | §27.4, and §36.4 for this round's additions |
| `backend/tests/security/test_pipeline_contract.py` | CREATE | Verifies INFRA-1, INFRA-2, INFRA-4 — the two workflows, the deployment script and the Terraform definitions | §36.2.9 |
| `backend/tests/security/test_database_boundary.py` | CREATE | Verifies the four engine bounds applied at the database boundary — connect timeout, pool wait, recycle age and pre-ping | §35.2.5 |
| `backend/tests/security/test_documentation_citations.py` | CREATE | Verifies Rule 1 and Rule 3 — that every cited line still carries the construct named, that no withdrawn citation survives, that each cross-referenced document exists, and that no document claims the rotation is complete | §36.7.1 |

Counted subtotal: **26** rows. Of these, 19 are test modules, 4 are configuration or
ignore files, 2 are lock or support files, and 1 is application source. 25 of the 26 are
present in the tree; the withdrawn provider lock file is the one that is not.

**Paths delivered by later rounds.** The table above is the set that existed when it
was measured. Rounds after it delivered sixty-one further paths that the plan does not
name either, and the forward axis is only complete if each is reachable from this
section too. None is counted among the 68, and none is counted among the 26 above.
Section 4.3 indexes the same sixty-one from the file side.

| Target path | Mode | Serves | Decision-log row |
|---|---|---|---|
| `.gitattributes` | CREATE | Rule 1, and every shell script a POSIX shell executes - the repository declared no line-ending policy, so what a `.sh` file held in a working tree was whatever the contributor's client was configured to do | Row 96.8.1 |
| `.github/scripts/check_frontend_lint_budget.js` | CREATE | INFRA-2 - the frontend warning ratchet: it judges the eslint report so a new warning fails the job while the eight the read-only source already carries do not | Row 88.7 |
| `.github/scripts/check_manifest_settings_contract.py` | CREATE | INFRA-2, C-4 - the standing check that the rendered configuration map declares every setting the model carries and no managed credential, held as a script so it runs identically in the pipeline and at a workstation | Row 88.5 |
| `.github/scripts/check_secret_policy.sh` | CREATE | C-4 - the committed-secret policy gate, which fails the build when a tracked file carries a credential pattern | Row 88.5 |
| `backend/app/core/admin_provisioning.py` | CREATE | H-1 - the idempotent administrator credential step, held apart from the revision that grants the role so that neither can silently do the other's work | Row 38.1 |
| `backend/app/core/db_contract.py` | CREATE | C-1, INFRA-5 - the database configuration contract the settings class and the migration environment both hold a value to, so a target or a bound one would refuse is refused by the other rather than defaulted | Rows 89.5, 89.6 |
| `backend/app/core/hashing.py` | CREATE | H-1 - the bcrypt primitive the request path and the administrator credential command both hash through, so the command needs no application setting to write a credential in the stored format | Row 89.7 |
| `backend/migrations/versions/0003_add_workload_indexes.py` | CREATE | The unindexed predicates the performance and resource round measured | Row 81.2 |
| `backend/migrations/versions/0004_add_open_intent_uniqueness.py` | CREATE | H-2, F3 - the read-then-insert race on the subscription creation route, which let two concurrent requests record two open payment intents for one plan | Row 94.6.1 |
| `backend/migrations/versions/0005_add_login_attempt_slots.py` | CREATE | M-1, F6 - the login refusal branches that issued no database statement, leaving the branch that counted a failed attempt distinguishable by elapsed time | Row 94.7.1 |
| `backend/requirements-audit.txt` | CREATE | INFRA-5 - the audit instrument held in a manifest of its own, so that the scanner's own dependency tree is not audited as this project's | Row 94.1.1 |
| `backend/tests/integration/__init__.py` | CREATE | Package marker for the integration suite the PostgreSQL job collects | Row 84.3.1 |
| `backend/tests/integration/test_postgres_migrations.py` | CREATE | Verifies H-1 against a real PostgreSQL 13 service: the revision chain, its reversals and what persists across them | Row 84.3.1 |
| `backend/tests/security/test_admin_provisioning.py` | CREATE | Verifies H-1 - the credential step is idempotent and prints no password | Row 84.3.1 |
| `backend/tests/security/test_deck_contract.py` | CREATE | Verifies Rule 2 - the presentation's structure, section count and theme | Row 84.3.1 |
| `backend/tests/security/test_delivery_pipeline.py` | CREATE | Verifies INFRA-1, INFRA-2 and INFRA-4 as delivered: the manifest inventory, the probes, the resource and scaling declarations and the image handling | Row 84.3.1 |
| `backend/tests/security/test_delivery_surface_contract.py` | CREATE | Verifies INFRA-2 and INFRA-4 - the delivery surface's probes, pipelines and governance accuracy | Row 84.3.1 |
| `backend/tests/security/test_documentation_accuracy_contract.py` | CREATE | Verifies Rule 1 - every documented gate, count and contact is the delivered one | Row 84.3.1 |
| `backend/tests/security/test_documentation_contract.py` | CREATE | Verifies Rule 1 and C-1 - no document generates a secret onto a terminal, and the runtime pin inventory is asserted against the files rather than itself | Row 84.3.1 |
| `backend/tests/security/test_infrastructure_contract.py` | CREATE | Verifies INFRA-1 - the Terraform surface the release paths depend on | Row 84.3.1 |
| `backend/tests/security/test_operator_documentation.py` | CREATE | Verifies Rule 1 - the operator-facing documents describe what ships, and the documented bootstrap blocks are executed rather than read | Row 84.3.1 |
| `backend/tests/security/test_pipeline_audit_contract.py` | CREATE | Verifies INFRA-2 - the audit and static-analysis gates the pipeline runs | Row 84.3.1 |
| `backend/tests/security/test_presentation_contract.py` | CREATE | Verifies Rule 2 - the presentation's claims against the tree they describe | Row 84.3.1 |
| `backend/tests/security/test_release_automation_contract.py` | CREATE | Verifies INFRA-4 - the release script and the delivery workflow, including the tool preflight and the bounded remote calls | Row 84.3.1 |
| `backend/tests/security/test_release_contract.py` | CREATE | Verifies INFRA-2 and INFRA-4 - the release path from build to rollout | Row 84.3.1 |
| `backend/tests/security/test_release_path_contract.py` | CREATE | Verifies INFRA-2 and INFRA-4 - image publication, digest confirmation and rollout | Row 84.3.1 |
| `backend/tests/security/test_residual_risk_guards.py` | CREATE | Verifies the two compensating-control guards the accepted advisories rest on | Row 84.3.1 |
| `backend/tests/security/test_security_documentation.py` | CREATE | Verifies Rule 1 - the disclosure policy and the residual-risk register | Row 84.3.1 |
| `backend/tests/security/test_terraform_contract.py` | CREATE | Verifies INFRA-1 - Secret Manager, the database, the cluster and the function | Row 84.3.1 |
| `infrastructure/functions/health/main.py` | CREATE | INFRA-1, INFRA-4 - the function handler, kept on the pinned `python39` runtime and reachable only through the restricted invoker binding | Row 37.13 |
| `infrastructure/functions/health/requirements.txt` | CREATE | INFRA-5 - the function's own pinned manifest, so its dependency set is inventoried like the service's | Row 37.13 |
| `infrastructure/kubernetes/00-namespace.yaml` | CREATE | INFRA-1, INFRA-4 - the namespace every other object is applied into | Row 88.1 |
| `infrastructure/kubernetes/10-service-accounts.yaml` | CREATE | INFRA-1, INFRA-4 - the three workload identities, each annotated for the account Terraform declares | Row 88.1 |
| `infrastructure/kubernetes/20-backend-config.yaml` | CREATE | INFRA-1, INFRA-4 - every non-credential setting the model carries, declared rather than defaulted | Row 88.1 |
| `infrastructure/kubernetes/30-backend-secrets.yaml` | CREATE | INFRA-1, INFRA-4 - the six managed credentials, mounted from the provider with no synchronised Secret | Row 88.1 |
| `infrastructure/kubernetes/35-migration-secrets.yaml` | CREATE | INFRA-1, INFRA-4 - the one credential the migration job needs, scoped to it | Row 88.1 |
| `infrastructure/kubernetes/40-backend.yaml` | CREATE | INFRA-1, INFRA-4 - the backend Deployment and its Service, with all three probes | Row 88.1 |
| `infrastructure/kubernetes/45-backend-hpa.yaml` | CREATE | INFRA-1, INFRA-4 - the backend replica range | Row 88.1 |
| `infrastructure/kubernetes/50-frontend.yaml` | CREATE | INFRA-1, INFRA-4 - the frontend Deployment and its Service, with all three probes | Row 88.1 |
| `infrastructure/kubernetes/55-frontend-hpa.yaml` | CREATE | INFRA-1, INFRA-4 - the frontend replica range | Row 88.1 |
| `infrastructure/kubernetes/60-migration-job.yaml` | CREATE | INFRA-1, INFRA-4 - the one-shot migration, named per release and bounded by a deadline | Row 88.1 |
| `infrastructure/kubernetes/65-ingestion-cronjob.yaml` | CREATE | INFRA-1, INFRA-4 - the scheduled ingestion workload, reading its credentials from mounted files | Row 88.1 |
| `infrastructure/kubernetes/70-admin-credential-job.yaml` | CREATE | INFRA-1, INFRA-4 - the administrator credential step, run as its own job | Row 88.1 |
| `infrastructure/k8s/README.md` | UPDATE | INFRA-1 - the record of where the manifests went, kept so that a reference in an older document leads somewhere rather than nowhere | Row 88.1 |
| `infrastructure/k8s/backend-deployment.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/backend-hpa.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/backend-service.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/backend.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/config.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/frontend-deployment.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/frontend-hpa.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/frontend-service.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/frontend.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/ingestion-cronjob.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/jobs/backend-migration-job.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/migration-job.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/namespace.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/secrets.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `infrastructure/k8s/serviceaccount.yaml` | DELETE | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` | Row 88.1 |
| `scripts/render_kubernetes_manifests.sh` | CREATE | INFRA-1, INFRA-4 - the one substitution pass both delivery paths invoke, and the authority for which manifests belong to which render group | Row 88.3 |
| `scripts/render_manifests.sh` | DELETE | INFRA-4 - the retired duplicate of that pass; row 82.7's decision is upheld with one implementation rather than two | Row 88.3 |

### 2.10 Delivered-path reconciliation

The plan's 68 is a count of plan entries. This is the count of paths the delivered tree
actually carries. It is one measurement of one tree, and it is the figure this repository
quotes: `git diff --name-status a26f7fb HEAD`, with the working tree clean, so nothing is
outstanding for `git status --porcelain` to add and no scratch file is in reach.

**The current measurement.**

**Read the first table below as the measurement of the round that published it, and the
second as the current figure.** The first is kept because several sibling documents quote
its arithmetic and a reader meeting `86` needs somewhere that explains it; it is not a
statement about this tree.

| Quantity | Count, as measured then |
|---|---|
| Planned CREATE and UPDATE entries (§2.1–§2.6) | **59** |
| — of those, delivered | **59** |
| — of those, still pending | **0** |
| Planned REFERENCE entries (§2.7) | **9** |
| — of those, unmodified as the plan requires | **8** |
| — of those, modified in delivery | **1** |
| Paths delivered beyond the plan (§2.9, both tables) | **87** |
| — of those, carried by the current tree | **70** |
| — of those, retired by the manifest consolidation | **17** |
| **Delivered paths in total** | **130** |
| — created | **100** |
| — modified | **30** |
| — deleted | **0** |
| Rows in the reverse index (sections 4, 4.1 and 4.3) | **156** |
| — of those, delivered paths | **130** |
| — of those, read-only references confirmed unmodified | **9** |
| — of those, retired by the manifest consolidation | **17** |
| Delivered paths absent from the reverse index | **0** |

`59 + 27 + 61 - 17 = 130` forward, the identity section 6.1 states and the only one this
document publishes for the delivered total: the plan's 59 changed entries, the 27 paths
sections 6.2 to 6.4 enumerate beyond it — 26 created plus the one read-only path delivery
modified — the 61 the rounds after them delivered, less the 17 the manifest consolidation
withdrew. `130 + 9 + 17 = 156` for the index, and `69 + 26 + 61 = 156` counting its three
tables directly. The plan's own arithmetic is `30 + 29 + 0 + 9 = 68`, unchanged by any of
this because it counts intentions rather than paths.

The 17 index rows that are not delivered paths are there because each names a path this
work created and a later round withdrew: the 15 manifests under `infrastructure/k8s/`,
`scripts/render_manifests.sh`, and `infrastructure/terraform/.terraform.lock.hcl`. The
first sixteen carry mode DELETE in section 2.9 and are recorded at
`infrastructure/k8s/README.md`; the lock file carries an explicit withdrawal, because the
provider version constraint it locked was reverted with it. A reader following any of them
finds why it is gone rather than nothing at all.

**Six earlier delivered-path totals, labelled as superseded snapshots.** Each was a
correct measurement of the tree that existed when it was taken, and each is retained only
so that a figure quoted elsewhere can be identified rather than reconciled.

| Snapshot | Status | What it measured |
|---|---|---|
| **86** — `59 + 26 + 1` | **Superseded** | The delivered set when section 2.9 held one table of 26 additions |
| **91** | **Superseded** | The introduction's figure one round later |
| **93** — `69 + 24` | **Superseded** | The reverse index when it was a single table |
| **141** — `59 + 1 + 25 + 56` | **Superseded** | The tree before the manifest consolidation withdrew 17 paths, and excluding the provider lock file as metadata |
| **125** — `60 + 65` | **Superseded** | The tree before the concurrency, provisioning and final-assessment rounds delivered four further paths, and while the provider lock file was still committed |
| **129** — `60 + 69` | **Superseded** | The tree before this round delivered `.gitattributes` |
| **130** — `60 + 70` | **Current** | This measurement, which the table above publishes |

One difference accounts for the whole gap between 141 and 129: the consolidation withdrew
17 paths that the 141 counted as present, which is a real reduction in the delivered
surface rather than a recount. `infrastructure/terraform/.terraform.lock.hcl` is counted by
neither. The 141 excluded it as provider metadata; the 125 counted it while it was
committed; and it is now absent from the tree, because the provider version constraint it
locked was itself a change made without authorisation and was reverted with it. It is
therefore one of the 17, indexed with its withdrawal stated rather than dropped.

**This supersedes `docs/security/DECISION_LOG.md` §23.1.** That section, written mid-work,
records 58 changed paths, 47 planned-and-delivered, 11 unplanned and 12 planned paths still
pending, and projects 70 as the figure downstream documents should use. Every figure in it
has moved: every planned path is now delivered, the unplanned set has grown from 11 to 87,
and the delivered total is 130 rather than the projected 70. The projection was sound
arithmetic on the information available; it is superseded by measurement, and the table
above is the figure to quote. `docs/security/DECISION_LOG.md` row 36.1.4 records the
decision that this file rather than that log is where a delivered-path count is maintained.

### 2.11 Rows kept for chronology and excluded from the total

Seventeen reverse-index rows name a path that is not in the tree. They are listed here
once, so that a reader who meets one of them in section 4.3 can tell at a glance which
kind it is, and so the exclusion in section 2.10 is checkable rather than asserted.

**Retired by the consolidation at [`DECISION_LOG.md`](DECISION_LOG.md) row 88.1 — sixteen
paths**, fifteen manifests and one render script:

`infrastructure/k8s/namespace.yaml`, `serviceaccount.yaml`, `config.yaml`, `secrets.yaml`,
`backend.yaml`, `backend-deployment.yaml`, `backend-service.yaml`, `backend-hpa.yaml`,
`frontend.yaml`, `frontend-deployment.yaml`, `frontend-service.yaml`, `frontend-hpa.yaml`,
`migration-job.yaml`, `jobs/backend-migration-job.yaml`, `ingestion-cronjob.yaml`, and
`scripts/render_manifests.sh`.

Two facts about this set are worth stating exactly, because both are checkable and neither
is what a reader would assume. First, **none of the fifteen manifests was ever committed**:
`git log --all --name-only -- "infrastructure/k8s/*.yaml"` returns nothing, so they existed
only in the working tree of the round that wrote them. Second, their disposition is
recorded in the tree rather than inferred here —
[`infrastructure/k8s/README.md`](../../infrastructure/k8s/README.md) states that the
autoscalers and the ingestion schedule were unique to that directory and were carried
across into the surviving substitution style, and that everything else duplicated an object
`infrastructure/kubernetes/` already declared and was dropped rather than reconciled twice.
That README also carries the object-to-manifest-to-render-group table, so it, and not this
section, is where a per-object mapping belongs. Individual replacements are deliberately
not asserted here: the source files are unreadable at every revision, so any per-file
mapping would be inference presented as record.

`infrastructure/k8s/README.md` is **not** in this list: it is delivered, and it exists so
that a reference to the old directory in an older document leads somewhere.

**Withdrawn with the provider-pinning revert — one path.**
`infrastructure/terraform/.terraform.lock.hcl` recorded resolved provider hashes for a
provider version constraint that `infrastructure/terraform/main.tf` no longer declares.
Pinning the provider was a scope change this work was not authorised to make, so it was
reverted, and the lock file went with it: a lock over a constraint that does not exist
locks nothing. It is absent from the tree and ignored by `.gitignore`, and both its rows
state the withdrawal rather than being deleted, so a reader meeting the path in an earlier
document reaches the reason. Row 91.1.1 records the revert.

One path that earlier revisions of this section named is no longer indexed at all.
`infrastructure/kubernetes/secret-provider-class.yaml` was recorded as created and never
was, and its two rows were removed rather than corrected in place, because nothing was
missing as a result: the object it claimed is declared inline as `kind: SecretProviderClass`
in `infrastructure/kubernetes/30-backend-secrets.yaml`,
`infrastructure/kubernetes/35-migration-secrets.yaml` and
`infrastructure/kubernetes/70-admin-credential-job.yaml`, which is why nothing ever
referenced the standalone file.

---

## 3. Axis 2 — old construct to new construct

This is the source-construct-to-target-implementation mapping Rule 1 asks for, covering
the three dependency replacements and the constructs the findings turn on. Every location
in the "Baseline location" column was read back from revision `a26f7fb` rather than copied
from a summary, and each is cited as measured fact.

| Old construct | Baseline location | New construct | Belongs to |
|---|---|---|---|
| `from jose import jwt` | `backend/app/core/security.py:2` | `import jwt`, resolving to PyJWT | `python-jose` replacement |
| `except jwt.JWTError:` | `backend/app/core/security.py:42` | The PyJWT exception base class | `python-jose` replacement |
| `from passlib.context import CryptContext` | `backend/app/core/security.py:3` | `import bcrypt` | `passlib` replacement |
| `pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')` | `backend/app/core/security.py:11` | Deleted; no shared context object replaces it | `passlib` replacement |
| `pwd_context.verify` and `pwd_context.hash` | `backend/app/core/security.py:15` and `:18` | `bcrypt.checkpw` and `bcrypt.hashpw`, with both wrapper signatures preserved so the calling module needs no change | `passlib` replacement |
| `algorithm=settings.ALGORITHM` and `algorithms=[settings.ALGORITHM]` | `backend/app/core/security.py:27` and `:34` | The validated algorithm allowlist | C-2 |
| `to_encode.update({"exp": expire})`, adding `exp` alone | `backend/app/core/security.py:26` | The same expiry plus `iss`, `aud`, `iat`, `nbf` and `jti`, each required on decode | C-2, H-7 |
| `payload.get("sub")` holding an email, against `User.id == user_id` holding an integer | `backend/app/core/security.py:35` versus `:48` | The stringified integer user identifier, matching the type of the column it is compared against | H-7 |
| `HTTPException(status_code=404, detail="User not found")` | `backend/app/core/security.py:50` | 401, indistinguishable from the response to an invalid token | M-1 |
| `ALGORITHM: str`, singular and unvalidated | `backend/app/core/config.py:7` | `JWT_ALGORITHMS`, a validated allowlist | C-2 |
| `import paypalrestsdk` | `backend/app/services/paypal_service.py:1` | `import httpx`, with the module path retained | `paypalrestsdk` replacement |
| `process_payment` | `backend/app/api/endpoints/subscriptions.py:7` and `:24` | `create_order` and `capture_order`. **This is a repair, not a rename** — see section 3.1 | `paypalrestsdk` replacement, H-2 |
| `import requests` | `backend/app/services/zillow_service.py:1` | `import httpx` | M-4, dependency removal |
| `JWT_SECRET` | `infrastructure/docker/docker-compose.yml:31` | `SECRET_KEY` | C-1, C-4 |
| `Base.metadata.create_all(bind=engine)` | `backend/app/main.py:18`, invoked at `:33` | The Alembic revision chain, which owns the schema instead | H-1 |

### 3.1 The `process_payment` row is a repair, not a rename

This is the single most consequential accuracy point in this file, and stating it loosely
would misrepresent an import-time fault as a cosmetic change.

`backend/app/services/paypal_service.py` was read end to end at revision `a26f7fb`. It
defines exactly two functions: **`create_payment`** at `:9` and **`execute_payment`** at
`:41`. **`process_payment` never existed.** The symbol
`backend/app/api/endpoints/subscriptions.py:7` imports is absent from the module it
imports from, and `:24` then calls it. That is one of the import-time faults that stopped
the application starting, which is why the row above maps a non-existent symbol onto two
new functions rather than describing a substitution between two working ones.

Two related facts about the same module, both verified at the same revision:

- `execute_payment(payment_id: str, payer_id: str)` at `:41-47` takes **both** parameters
  from the caller and performs **no ownership lookup at all** — it resolves the identifier
  with the provider and executes. That shape is finding H-3 exactly.
- The return annotation at `:9` names a type the module never imports, so the module
  raises on import independently of the missing symbol. Both faults sit in a file the plan
  rewrites for a security reason, so neither widens the change surface.

### 3.2 Supporting notes on three rows

**The `JWT_SECRET` to `SECRET_KEY` row is a name change, and only names appear here.** The
application reads `SECRET_KEY`, so `infrastructure/docker/docker-compose.yml:31` supplies
a value under a name the application never reads — the secret does not reach the
application at all, leaving it to fall back on whatever the environment file holds.
Repairing the name is therefore a precondition for the weak-key control of C-1 to have any
effect in a containerised deployment, rather than a tidying change. No value from that file
or from any line cited in this document is reproduced anywhere in it.

**The configuration module declared eight settings and zero validators.**
`backend/app/core/config.py:4-12` declares `DATABASE_URL`, `SECRET_KEY`, `ALGORITHM`,
`ACCESS_TOKEN_EXPIRE_MINUTES`, `ZILLOW_API_KEY`, `PAYPAL_CLIENT_ID`,
`PAYPAL_CLIENT_SECRET` and `SENTRY_DSN` — eight in total — and validates none of them,
which is the shared root of C-1, C-2 and C-3. Separately, four settings that other modules
read at import time were **not declared at all**: the CORS origin list, the Zillow API URL,
the SendGrid key and the sender address. The first is read at `backend/app/main.py:25` and
the second at `backend/app/services/zillow_service.py:6`.

**The two ownership predicates in the filter endpoints are unchanged.**
`user_id=current_user.id` at `backend/app/api/endpoints/filters.py:21` and
`FilterModel.user_id == current_user.id` at `:33` were already correct and are byte-identical
after the work. They appear in Axis 2 as a deliberate non-transformation: they are the
object-level pattern that `backend/app/core/authorization.py` generalizes, which is why
that module's row in section 2.1 cites this file as its source. `docs/security/DECISION_LOG.md`
rows 12.2 and 34.8.1 record the position and the one clause of it that was withdrawn.

---

## 4. Reverse index — target file to finding to verifying test

This section is what makes the matrix bidirectional over the plan's own entries. Sections
1 to 3 run forward from a finding to the files and constructs that answer it; this table
runs backward, so a reader holding a file in hand can establish which finding it exists to
remediate and which test proves it did. Every target path from sections 2.1 to 2.7 appears
exactly once, in the same order. Where a path carries no finding, its governing authority
is recorded instead, so no cell is empty.

**69 rows, and what they are.** They are the plan's 59 changed entries, its 9 read-only
authorities and the contextual `backend/app/api/router.py` row that section 2.1 renders —
so this table is one row longer than the plan's 68 entries, for the reason section 2.8
gives. **The paths delivered beyond the plan are indexed separately**, in sections 4.1 and
4.3, because they belong to a different population and mixing them in would make this
table's row count stop matching the plan it reconciles against. Section 2.10 adds the three
tables together and states what each contributes.

| Target path | Finding remediated, or governing authority | Verifying test or command |
|---|---|---|
| `backend/app/core/config.py` | C-1, C-2, C-3, H-5, M-3 | `test_config_validation.py`, `test_settings_and_redaction.py` |
| `backend/app/core/security.py` | C-2, H-7, M-1 | `test_jwt_hardening.py`, `test_token_hardening.py` |
| `backend/app/core/authorization.py` | H-1 | `test_rbac_matrix.py`, `test_authorization.py` |
| `backend/app/core/logging.py` | M-4 | `test_settings_and_redaction.py`, `test_services.py` |
| `backend/app/core/plans.py` | H-2 | `test_subscription_tampering.py` (`test_h2_*`) |
| `backend/app/main.py` | M-2, M-3 | `test_application_surface.py`, `test_settings_and_redaction.py` |
| `backend/app/api/endpoints/auth.py` | H-7, M-1 | `test_jwt_hardening.py`, `test_login_lockout_and_rate_limit.py`, `test_login_throttling_and_timing.py` |
| `backend/app/api/endpoints/listings.py` | H-1, H-5, H-6 | `test_rbac_matrix.py`, `test_request_bounds_and_refusals.py`, `test_mass_assignment.py` |
| `backend/app/api/endpoints/filters.py` | H-1 | `test_rbac_matrix.py`, including its cross-tenant cases |
| `backend/app/api/endpoints/subscriptions.py` | H-1, H-2, H-3, H-4 | `test_subscription_tampering.py`, `test_paypal_webhook.py`, `test_rbac_matrix.py` |
| `backend/app/api/router.py` | H-4, as negative evidence — deliberately unchanged, which is what shows the four prefixes are preserved | `test_rbac_matrix.py::test_the_matrix_covers_every_route_the_application_publishes` |
| `backend/app/services/paypal_service.py` | C-3, H-3, H-4 | `test_paypal_webhook.py`, `test_payment_lifecycle.py`, `test_config_validation.py` |
| `backend/app/services/zillow_service.py` | M-4 | `test_services.py`, `test_settings_and_redaction.py` |
| `backend/app/services/email_service.py` | M-4 | `test_services.py` |
| `backend/app/tasks/listing_updater.py` | M-4 | `test_tasks.py` |
| `backend/app/db/models.py` | H-1, H-3, H-4 | `test_rbac_matrix.py`, `test_migrations.py`, `test_paypal_webhook.py` |
| `backend/app/db/database.py` | H-1, as the precondition that made verification possible | The startup gate `python -c "import backend.app.main"` |
| `backend/app/schema/user.py` | C-1, H-7 | `test_mass_assignment.py`, `test_config_validation.py` |
| `backend/app/schema/listing.py` | H-6 | `test_mass_assignment.py` |
| `backend/app/schema/filter.py` | H-6 | `test_mass_assignment.py` |
| `backend/app/schema/subscription.py` | H-2 | `test_subscription_tampering.py` (`test_h2_*`) |
| `backend/requirements.txt` | INFRA-5 | `pip-audit -r backend/requirements.txt` |
| `backend/requirements-dev.txt` | INFRA-5 | `pip-audit -r backend/requirements-dev.txt`; `test_services.py`, whose module-scope imports depend on the client types this manifest declares |
| `backend/alembic.ini` | H-1 | `alembic upgrade head`, then one `alembic downgrade -1` per revision in the chain — **five** reversals, the chain being `0001` to `0005`; `test_migration_gate.py::test_each_revision_reverses_and_the_chain_re_applies` walks it a step at a time, and the workflow instead runs `downgrade -1` followed by `downgrade base` so it reaches the empty schema without counting revisions |
| `backend/migrations/env.py` | H-1 | `test_migrations.py` |
| `backend/migrations/script.py.mako` | H-1 | `test_revision_contracts.py` |
| `backend/migrations/versions/0001_add_rbac_and_subscription_columns.py` | H-1, H-3, H-4 | `test_migrations.py`, `test_migration_revisions.py` |
| `backend/migrations/versions/0002_seed_single_admin.py` | H-1 | `test_admin_seed_migration.py`, asserting the ordered address list holding the role equals exactly `['test@blitzy.com']` after the grant, and equals `[]` after its reversal |
| `backend/tests/conftest.py` | Fixtures for every finding, and the repository-root `sys.path` bootstrap the CI invocation needs | `pytest backend/tests -q` from the repository root **and** from `backend/`, the second of which reported `ModuleNotFoundError: No module named 'backend'` for all ten modules without this file |
| `backend/tests/security/__init__.py` | Package marker for the security suite | `pytest backend/tests/security -q` |
| `backend/tests/security/test_jwt_hardening.py` | Verifies C-2, H-7, M-1 | Self-verifying; run by `pytest backend/tests/security -q` |
| `backend/tests/security/test_rbac_matrix.py` | Verifies H-1, H-5 | Self-verifying; `test_the_matrix_is_nine_routes_by_five_principals` asserts the 9 by 5 shape the 45 assertions rest on |
| `backend/tests/security/test_subscription_tampering.py` | Verifies H-2, H-3 | Self-verifying; cases named `test_h2_*` and `test_h3_*` so each finding is locatable without reading the bodies |
| `backend/tests/security/test_paypal_webhook.py` | Verifies H-4 | Self-verifying; drives the verification function directly, since the provider does not support postback verification for simulated events |
| `backend/tests/security/test_mass_assignment.py` | Verifies H-1, H-6 | Self-verifying; includes the negative proof that a registration body carrying a role field still yields the default role |
| `backend/tests/security/test_config_validation.py` | Verifies C-1, C-2, C-3 | Self-verifying; asserts startup failure for an undersized key, the `your_secret_key_here` placeholder, an algorithm outside the allowlist, and a production environment paired with sandbox payment credentials |
| `backend/tests/security/test_login_lockout_and_rate_limit.py` | Verifies M-1 | Self-verifying |
| `backend/tests/test_api.py` | Regression cover for H-1, H-5, M-3 and the frozen login response shape | Self-verifying |
| `backend/tests/test_services.py` | Verifies M-4 | Self-verifying; asserts the Zillow key travels in a header and appears in no URL or log record |
| `backend/tests/test_tasks.py` | Verifies M-4 and that the ingestion workflow still functions | Self-verifying |
| `.gitignore` | C-4 | `git check-ignore` over the paths it must cover |
| `.dockerignore` | C-4, INFRA-3 | The container build verification |
| `.env.example` | C-1, C-4 | `test_deployment_contract.py`, `test_settings_and_redaction.py` |
| `infrastructure/docker/docker-compose.yml` | C-1, C-4 | `test_deployment_contract.py`, including `test_every_declared_value_is_an_environment_substitution` and `test_the_proxy_mounts_no_credential_from_this_repository` |
| `infrastructure/docker/Dockerfile.backend` | INFRA-3, INFRA-5 | The container build verification; `test_deployment_contract.py` |
| `infrastructure/terraform/main.tf` | C-4, INFRA-1 | `terraform fmt -check`, `terraform validate`, `test_pipeline_contract.py` |
| `infrastructure/terraform/variables.tf` | INFRA-1 | `terraform validate`, `test_pipeline_contract.py` — every added variable declared with a validation rule |
| `infrastructure/terraform/outputs.tf` | INFRA-1 | `terraform validate`, which fails at baseline on this file's dangling references; `test_pipeline_contract.py` asserts no output carries a secret value |
| `.github/workflows/ci.yml` | INFRA-2 | The gates it runs: `pip-audit --strict` against both manifests, `bandit -r backend/app -ll`, `flake8`, the full backend suite, the security suite, the database-backed integration check, and the two compensating-control guards; plus `test_pipeline_contract.py` |
| `.github/workflows/cd.yml` | INFRA-2, C-4 | `test_pipeline_contract.py` — the `permissions` and `concurrency` blocks, the gate on the reusable CI workflow, the federated-identity exchange, each `docker build` naming a Dockerfile that exists, the registry host, the regional cluster flag, the workload preflight, migrations before the rollout, and the readiness probe |
| `scripts/deploy.sh` | INFRA-4 | `bash -n`, and `test_pipeline_contract.py` — strict shell options, no unauthenticated-invocation flag, no on-disk key activation, credentials and namespace asserted before any mutation, migrations before the rollout |
| `scripts/setup_dev_environment.sh` | C-1, C-4 | `test_setup_script.py`, `test_setup_script_bootstrap.py` |
| `docs/security/DECISION_LOG.md` | Rule 1 (Explainability) — decision-log clause | Review against Rule 1: every non-trivial decision carries alternatives, reasoning and risk |
| `docs/security/TRACEABILITY_MATRIX.md` | Rule 1 (Explainability) — bidirectional-matrix clause | The count checks in section 5 of this file |
| `docs/security/RESIDUAL_RISK.md` | The accepted-residual-risk instruction | `pip-audit -r backend/requirements.txt` reporting exactly the 7 documented advisories, plus the two compensating-control guards |
| `docs/security/CREDENTIAL_ROTATION.md` | C-4 | Manual confirmation that the documented order was followed |
| `docs/review/CRITICAL_DECISIONS.md` | Rule 3 (Critical Decision Review Document) | Review against Rule 3: five entries ordered highest risk first, each with alternatives, risk level and an assigned reviewer with named checks |
| `blitzy-deck/executive-summary.html` | Rule 2 (Executive Presentation); F-25 | `test_operator_documentation.py` asserts the readiness wording, the pending secret-delivery link and every Rule 2 structural bound; a headless-browser pass over all eighteen sections confirms both diagrams draw as SVG, all 47 icon placeholders resolve, no slide overflows and the console is silent |
| `SECURITY.md` | Disclosure policy and supported-version statement | Review for presence and accuracy of the disclosure contact and supported versions |
| `README.md` | C-1, C-4, and notice of the one intentional breaking change | Review that the breaking change is stated and the verification commands resolve |
| `frontend/src/services/auth.ts` | H-7 — read-only reference establishing the token-storage contract | Confirmed unmodified; absent from the changed set |
| `frontend/src/services/paypal.ts` | H-2 — read-only reference confirming no client sends an amount, and the authority for the product mismatch of O-6. **Not the evidence for the hosted redirect**, which is carried by `backend/app/schema/subscription.py`, `backend/app/api/endpoints/subscriptions.py` and `backend/app/services/paypal_service.py`; this file calls the provider's Billing Subscriptions product and never consumes the backend's `approval_url`. Corrected per `DECISION_LOG.md` row 92.10 | Confirmed unmodified; absent from the changed set |
| `frontend/src/schema/subscription.ts` | H-2 — read-only reference for the response shape | Confirmed unmodified; absent from the changed set |
| `frontend/src/utils/validators.ts` | C-1 — read-only reference for the documented password policy | Confirmed unmodified; absent from the changed set |
| `frontend/package.json` | INFRA-2 — read-only reference for the lock-file assumption | Confirmed unmodified; absent from the changed set |
| `infrastructure/docker/Dockerfile.frontend` | INFRA-3 — planned as a read-only reference for the same assumption; delivered as a modification | Present in the changed set. `backend/tests/security/test_deployment_contract.py` asserts both `ARG` declarations and that neither build argument carries a secret; see section 6.3 |
| `documentation/Technical Specifications.md` | H-1 — read-only design-intent authority for the four roles | Confirmed unmodified; absent from the changed set |
| `documentation/Software Requirements Specifications (SRS).md` | M-1 — read-only design-intent authority for the lockout parameters | Confirmed unmodified; absent from the changed set |
| `documentation/Software Project Proposal.md` | INFRA-2 — read-only design-intent authority for the coverage targets | Confirmed unmodified; absent from the changed set |

Test modules are named by file above rather than by full path, since every one resides in
`backend/tests/` or `backend/tests/security/` as sections 2.4 and 2.9 record.

### 4.1 Reverse index — the paths delivered beyond the plan

The table above covers the plan's own paths. This one covers the 26 rows of section 2.9's
first table from the same backward direction, so that a reader holding any file in the
delivered tree — not only a planned one — can establish what it exists for and what proves
it. Every row of that table appears here exactly once, in the same order, including the one
whose creation was later reverted; its row records the withdrawal rather than dropping it,
so a citation of the path still leads somewhere.

| Target path | Finding remediated, or governing authority | Verifying test or command |
|---|---|---|
| `backend/app/core/rate_limit.py` | H-5, and the bounded credential throttle | `test_rate_limit_store.py`, `test_request_bounds_and_refusals.py`, `test_login_throttling_and_timing.py`, `test_settings_and_redaction.py` |
| `backend/.dockerignore` | C-4, INFRA-3 | `test_deployment_contract.py`, `test_pipeline_contract.py`; parity with the root file verified by comparison |
| `frontend/.dockerignore` | C-4, INFRA-3 | `test_deployment_contract.py`, `test_pipeline_contract.py` |
| `frontend/package-lock.json` | INFRA-2 — `npm ci` in the frontend image and the pipeline both require it | The frontend install step in `.github/workflows/ci.yml` |
| `setup.cfg` | Rule 1, and the gate definitions the tooling reads | `flake8 backend`, `pytest` honouring `asyncio_mode = strict` and the coverage floor; parsed by `test_pipeline_contract.py` |
| `infrastructure/terraform/.terraform.lock.hcl` | INFRA-1 — **withdrawn, absent from the tree**: the provider version constraint it locked was reverted with it (row 91.1.1) | `test_pipeline_contract.py::test_the_provider_selection_is_not_locked_in_the_repository` asserts the absence; `terraform init -backend=false` then `terraform validate` resolves providers without it |
| `backend/tests/support.py` | Rule 1 — one module object for the shared test values | `test_api.py::test_the_shared_test_values_are_held_by_one_module_object` |
| `backend/tests/security/test_token_hardening.py` | Verifies C-2, H-7 | Self-verifying |
| `backend/tests/security/test_authorization.py` | Verifies H-1 at unit level | Self-verifying |
| `backend/tests/security/test_payment_lifecycle.py` | Verifies C-3, H-3, H-4 | Self-verifying; includes the two withdrawn-settlement notifications and their no-state-change and idempotency cases |
| `backend/tests/security/test_login_throttling_and_timing.py` | Verifies M-1 | Self-verifying |
| `backend/tests/security/test_request_bounds_and_refusals.py` | Verifies H-5, H-6 | Self-verifying |
| `backend/tests/security/test_settings_and_redaction.py` | Verifies C-1, C-2, C-3, M-3, M-4 | Self-verifying; includes `test_credential_never_reaches_the_stream` |
| `backend/tests/security/test_application_surface.py` | Verifies M-2, M-3 | Self-verifying; includes `TestRouteMatchingFailsClosed` |
| `backend/tests/security/test_migrations.py` | Verifies H-1 | Self-verifying; executes every revision in the chain against in-memory SQLite |
| `backend/tests/security/test_migration_gate.py` | Verifies H-1 — the schema is owned by migrations, not by import-time creation | Self-verifying |
| `backend/tests/security/test_migration_revisions.py` | Verifies H-1, H-3, H-4 | Self-verifying |
| `backend/tests/security/test_revision_contracts.py` | Verifies H-1 — the template and the revision chain | Self-verifying |
| `backend/tests/security/test_admin_seed_migration.py` | Verifies H-1 — the ordered address list holding the role, asserted to equal exactly the one address the grant names | Self-verifying |
| `backend/tests/security/test_rate_limit_store.py` | Verifies H-5 — the bounded key ceiling | Self-verifying |
| `backend/tests/security/test_setup_script.py` | Verifies C-1, C-4 | Self-verifying |
| `backend/tests/security/test_setup_script_bootstrap.py` | Verifies C-1, C-4 | Self-verifying |
| `backend/tests/security/test_deployment_contract.py` | Verifies C-1, C-4, INFRA-3 | Self-verifying; the five-service profile inventory is itself the contract |
| `backend/tests/security/test_pipeline_contract.py` | Verifies INFRA-1, INFRA-2, INFRA-4 | Self-verifying; reads the two workflows, the deployment script and the four Terraform files |
| `backend/tests/security/test_database_boundary.py` | Verifies the four engine bounds at the database boundary | Self-verifying; two deterministic behavioural cases plus the negative half proving `pool_pre_ping` produces the recovery |
| `backend/tests/security/test_documentation_citations.py` | Verifies Rule 1 and Rule 3 | Self-verifying; the expected `path:line` pairs are written out in the module rather than read from the document at run time |

### 4.2 Why these are indexed apart from the plan's entries

The table in section 4 covers every path the plan's transformation mapping enumerates.
The work also delivered paths the mapping does not name, and the reverse direction is
only complete if a reader holding one of those files can reach a finding from it too.
They are indexed in sections 4.1 and 4.3 rather than merged into section 4, so that the
30 / 29 / 0 / 9 breakdown and the figure 68 keep counting exactly what the plan counts.
**None of the rows in either is counted among the 68.**

`docs/security/DECISION_LOG.md` §23.2, row 31.11 and row 81.38 are the authority for why
each exists and what carrying it costs. Section 2.10 holds the measurement of how many
such paths there are and of how many paths this work has changed in total.

An earlier revision of this section carried a second copy of section 4.1's table,
written independently and listing nineteen of the same paths with different evidence.
Both readings are kept: the two rows that copy named and section 4.1 did not &mdash;
`backend/migrations/versions/0003_add_workload_indexes.py` and
`backend/tests/security/test_delivery_pipeline.py` &mdash; are indexed in section 4.3,
and the duplicate rows are gone so that the row count is a count of paths.

### 4.3 Reverse index &mdash; the paths delivered by later rounds

The same sixty-one paths section 2.9's second table lists, from the backward
direction. Every delivered path in the tree appears in section 4, section 4.1 or here,
exactly once across the three. Sixteen of the rows here carry a path a later round removed
— the manifests and the renderer the Kubernetes consolidation retired — and each says so,
so that the table can be read as an index of this work's history without being read as a
claim about the current tree. Section 2.10 counts those sixteen apart from the delivered
total.

| Target path | Finding remediated, or governing authority | Verifying test or command |
|---|---|---|
| `.gitattributes` | Rule 1 - the repository declared no line-ending policy, so a checkout could give a shell script a carriage return in its `#!` line (row 96.8.1) | `test_deployment_contract.py`, three cases: the two directives, `git check-attr` over the four POSIX-executed scripts, and `git ls-files --eol` over every tracked path |
| `.github/scripts/check_frontend_lint_budget.js` | INFRA-2 - the frontend lint gate could not tell a new warning from a known one | `node .github/scripts/check_frontend_lint_budget.js` on the report the `frontend` job writes; `backend/tests/security/test_delivery_surface_contract.py` |
| `.github/scripts/check_manifest_settings_contract.py` | INFRA-2, C-4 - the standing check that the rendered configuration map declares every setting the model carries and no managed credential, held as a script so it runs identically in the pipeline and at a workstation (row 88.5) | `test_delivery_pipeline.py`, which runs the gate itself and holds its recorded exemption against the manifests for equality; the `infrastructure` job in `.github/workflows/ci.yml`; run directly it prints the number of manifests it matched |
| `.github/scripts/check_secret_policy.sh` | C-4 - the committed-secret policy gate, which fails the build when a tracked file carries a credential pattern (row 88.5) | The `infrastructure` job in `.github/workflows/ci.yml`; `bash -n` parses it |
| `backend/app/core/admin_provisioning.py` | H-1 - the idempotent administrator credential step, held apart from the revision that grants the role so that neither can silently do the other's work (row 38.1) | `test_admin_provisioning.py`; `test_admin_seed_migration.py` for the exactly-one-administrator post-condition |
| `backend/app/core/db_contract.py` | C-1, INFRA-5 - the migration environment accepted any non-blank string as a database URL and replaced a malformed bound with a default, where the settings class refused both; one contract now holds each value to one rule (rows 89.5, 89.6) | `test_config_validation.py` through the settings model; `test_migration_revisions.py`, its refusal and connect-argument cases, through the migration environment; `test_database_boundary.py` for the rendered connection arguments |
| `backend/app/core/hashing.py` | H-1 - the administrator credential command reached its hashing through the request-path module, so it resolved `Settings` and could not start under the identity its own Job grants it (row 89.7) | `test_admin_provisioning.py`, its `TestTheCommandRunsOnWhatTheJobGrantsIt` class, which drives the command in a subprocess carrying only the Job's environment; `test_login_throttling_and_timing.py` for the request-path format, cost range and verification of an inherited hash |
| `backend/migrations/versions/0003_add_workload_indexes.py` | The unindexed predicates the performance and resource round measured (row 81.2) | `test_migration_revisions.py`, its `0003` cases; `test_migration_gate.py`; and `pg_indexes` on PostgreSQL 13 in both directions |
| `backend/migrations/versions/0004_add_open_intent_uniqueness.py` | H-2, F3 - the partial unique index that holds an account to one open payment intent per plan, closing the read-then-insert race the creation route allowed (row 94.6.1) | `test_migration_revisions.py`, its `0004` cases; `test_migration_gate.py` for the offline stream and the step-by-step reversal; and `TestOnlyOneOpenIntentPerPlan` in `test_payment_lifecycle.py`, whose two-connection case races two real requests on PostgreSQL 13 |
| `backend/migrations/versions/0005_add_login_attempt_slots.py` | M-1, F6 - the fixed, fully seeded throttling table that lets every login refusal take one write lock, issue one update and commit, so no branch is distinguishable by the statements it does or does not issue (row 94.7.1) | `test_migration_revisions.py`, its `0005` cases, including the assertion pinning the seeded count to `LOGIN_ATTEMPT_SLOT_COUNT`; `test_migration_gate.py` for the offline stream and the step-by-step reversal; and `TestRefusalBranchesDoTheSameWork` in `test_login_throttling_and_timing.py`, which counts the statements each of the four refusal branches issues |
| `backend/requirements-audit.txt` | INFRA-5 - `pip-audit` resolves a dependency tree of its own, and declaring it beside the test tooling reported six of the scanner's own advisories as this project's accepted residual risk (row 94.1.1) | `test_deployment_contract.py`; it is deliberately not audited, which `test_pipeline_audit_contract.py` asserts |
| `backend/tests/integration/__init__.py` | Package marker for the integration suite the PostgreSQL job collects (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/integration/test_postgres_migrations.py` | Verifies H-1 against a real PostgreSQL 13 service: the revision chain, its reversals and what persists across them (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_admin_provisioning.py` | Verifies H-1 - the credential step is idempotent and prints no password (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_deck_contract.py` | Verifies Rule 2 - the presentation's structure, section count and theme (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_delivery_pipeline.py` | Verifies INFRA-1, INFRA-2 and INFRA-4 as delivered: the manifest inventory, the probes, the resource and scaling declarations and the image handling (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_delivery_surface_contract.py` | Verifies INFRA-2 and INFRA-4 - the delivery surface's probes, pipelines and governance accuracy (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_documentation_accuracy_contract.py` | Verifies Rule 1 - every documented gate, count and contact is the delivered one (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_documentation_contract.py` | Verifies Rule 1 and C-1 - no document generates a secret onto a terminal, and the runtime pin inventory is asserted against the files rather than itself (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_infrastructure_contract.py` | Verifies INFRA-1 - the Terraform surface the release paths depend on (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_operator_documentation.py` | Verifies Rule 1 - the operator-facing documents describe what ships, and the documented bootstrap blocks are executed rather than read (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_pipeline_audit_contract.py` | Verifies INFRA-2 - the audit and static-analysis gates the pipeline runs (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_presentation_contract.py` | Verifies Rule 2 - the presentation's claims against the tree they describe (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_release_automation_contract.py` | Verifies INFRA-4 - the release script and the delivery workflow, including the tool preflight and the bounded remote calls (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_release_contract.py` | Verifies INFRA-2 and INFRA-4 - the release path from build to rollout (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_release_path_contract.py` | Verifies INFRA-2 and INFRA-4 - image publication, digest confirmation and rollout (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_residual_risk_guards.py` | Verifies the two compensating-control guards the accepted advisories rest on (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_security_documentation.py` | Verifies Rule 1 - the disclosure policy and the residual-risk register (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `backend/tests/security/test_terraform_contract.py` | Verifies INFRA-1 - Secret Manager, the database, the cluster and the function (row 84.3.1) | Self-verifying; run by `pytest backend/tests -q` |
| `infrastructure/functions/health/main.py` | INFRA-1, INFRA-4 - the function handler, kept on the pinned `python39` runtime and reachable only through the restricted invoker binding (row 37.13) | `test_terraform_contract.py`; `test_delivery_pipeline.py` for the deployment step that carries the pin |
| `infrastructure/functions/health/requirements.txt` | INFRA-5 - the function's own pinned manifest, so its dependency set is inventoried like the service's (row 37.13) | `test_terraform_contract.py`; `pip-audit` reads it as a manifest |
| `infrastructure/kubernetes/00-namespace.yaml` | INFRA-1, INFRA-4 - the namespace every other object is applied into (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/10-service-accounts.yaml` | INFRA-1, INFRA-4 - the three workload identities, each annotated for the account Terraform declares (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/20-backend-config.yaml` | INFRA-1, INFRA-4 - every non-credential setting the model carries, declared rather than defaulted (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/30-backend-secrets.yaml` | INFRA-1, INFRA-4 - the six managed credentials, mounted from the provider with no synchronised Secret (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/35-migration-secrets.yaml` | INFRA-1, INFRA-4 - the one credential the migration job needs, scoped to it (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/40-backend.yaml` | INFRA-1, INFRA-4 - the backend Deployment and its Service, with all three probes (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/45-backend-hpa.yaml` | INFRA-1, INFRA-4 - the backend replica range (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/50-frontend.yaml` | INFRA-1, INFRA-4 - the frontend Deployment and its Service, with all three probes (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/55-frontend-hpa.yaml` | INFRA-1, INFRA-4 - the frontend replica range (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/60-migration-job.yaml` | INFRA-1, INFRA-4 - the one-shot migration, named per release and bounded by a deadline (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/65-ingestion-cronjob.yaml` | INFRA-1, INFRA-4 - the scheduled ingestion workload, reading its credentials from mounted files (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/kubernetes/70-admin-credential-job.yaml` | INFRA-1, INFRA-4 - the administrator credential step, run as its own job (row 88.1) | `test_delivery_pipeline.py`; `.github/scripts/check_manifest_settings_contract.py`; rendered by `scripts/render_kubernetes_manifests.sh` |
| `infrastructure/k8s/README.md` | INFRA-1 - the record of where the manifests went, kept so that a reference in an older document leads somewhere rather than nowhere (row 88.1) | `test_delivery_pipeline.py` asserts the directory holds no manifest |
| `infrastructure/k8s/backend-deployment.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/backend-hpa.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/backend-service.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/backend.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/config.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/frontend-deployment.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/frontend-hpa.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/frontend-service.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/frontend.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/ingestion-cronjob.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/jobs/backend-migration-job.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/migration-job.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/namespace.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/secrets.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `infrastructure/k8s/serviceaccount.yaml` | INFRA-1, INFRA-4 - retired by the consolidation: the object it declared is declared once, in `infrastructure/kubernetes/` (row 88.1) | `test_delivery_pipeline.py` asserts one inventory and reads the render groups out of the renderer |
| `scripts/render_kubernetes_manifests.sh` | INFRA-1, INFRA-4 - the one substitution pass both delivery paths invoke, and the authority for which manifests belong to which render group (row 88.3) | `bash -n`; `test_delivery_pipeline.py`, its render-group cases; invoked by `.github/workflows/cd.yml` and `scripts/deploy.sh` |
| `scripts/render_manifests.sh` | INFRA-4 - the retired duplicate of that pass; row 82.7's decision is upheld with one implementation rather than two (row 88.3) | `test_delivery_pipeline.py` asserts a single renderer |
---

---

## 5. Axis 3 — the schema, construct by construct

Sections 1, 2 and 4 map the migrations at file level: revision `0001` carries
H-1, H-3 and H-4, and revision `0002` carries H-1. That is the right granularity
for a finding-to-file axis and the wrong granularity for a schema, because it
cannot answer the question a reviewer of a migration actually asks — *is every
construct the models declare produced by a revision, and is every construct a
revision produces declared by the models?*

This section answers that in both directions, per table, per column, per type,
per nullability, per default, per key and per constraint. Every row was read back
from the delivered code — by introspecting `Base.metadata` and by reading the two
revision files — rather than transcribed from the plan.

**Totals, measured.** 8 tables. 48 columns, of which 33 are `NOT NULL` and 15 are
nullable. 10 server defaults. 8 primary keys. 4 foreign keys. 3 uniqueness
constraints. 8 ORM relationships across 4 reciprocal pairs.

**Provenance of those 48 columns, measured.** 14 are introduced by this work and 34
precede it. The 14 divide by how they arrive: 7 are appended to a table that already
existed &mdash; 3 on `users` and 4 on `subscriptions` &mdash; 4 are carried by
`webhook_events`, the table revision `0001` creates, and 3 are carried by
`login_attempt_slots`, the table revision `0005` creates, so those seven exist only
where their table does. Only the 7 appended ones can be added to a populated table,
which is why they are the ones that need a server default; `webhook_events.received_at`
and two of the three slot columns carry one as well, giving the 10 counted above.

### 5.1 The revision that owns each table

Revision `0001` behaves differently depending on what it finds, which is why a
table has two possible provenances. On a database that already holds the six
tables that precede this work, it alters them. On an empty database it creates
them in full, carrying this revision's columns from the outset, and records what
it created in `alembic_0001_created_tables` so its downgrade drops exactly those.

| # | Table | Columns | Provenance on a legacy baseline | Provenance on an empty database | Model | Reverse: dropped by |
|---|-------|--------:|--------------------------------|---------------------------------|-------|---------------------|
| 5.1.1 | `users` | 8 | Precedes this work; `0001` adds 3 columns | `0001` `create_table` with all 8 | `User` | `0001` downgrade — 3 columns, or the whole table when it created it |
| 5.1.2 | `listings` | 11 | Precedes this work; unchanged by either revision | `0001` `create_table` with all 11 | `Listing` | `0001` downgrade — whole table only when it created it |
| 5.1.3 | `filters` | 5 | Precedes this work; unchanged | `0001` `create_table` with all 5 | `Filter` | as above |
| 5.1.4 | `criteria` | 5 | Precedes this work; unchanged | `0001` `create_table` with all 5 | `Criteria` | as above |
| 5.1.5 | `zip_codes` | 3 | Precedes this work; unchanged | `0001` `create_table` with all 3 | `ZipCode` | as above |
| 5.1.6 | `subscriptions` | 9 | Precedes this work; `0001` adds 4 columns and 1 uniqueness | `0001` `create_table` with all 9 | `Subscription` | `0001` downgrade — 4 columns and the uniqueness, or the whole table when it created it |
| 5.1.7 | `webhook_events` | 4 | **Added by `0001`** | Added by `0001` | `WebhookEvent` | `0001` downgrade — always dropped, on both paths |
| 5.1.8 | `alembic_0001_created_tables` | 1 | Not created — nothing was created | Created by `0001` when it created at least one table | None — bookkeeping only, deliberately absent from `Base.metadata` | `0001` downgrade, last, after the tables it records |
| 5.1.9 | `login_attempt_slots` | 3 | **Added by `0005`** | Added by `0005` | `LoginAttemptSlot` | `0005` downgrade — always dropped, on both paths |

### 5.2 Every column this work introduces

Fourteen columns. Seven are appended to two pre-existing tables &mdash; three on
`users` and four on `subscriptions` &mdash; and each of those seven carries a server
default, which is what makes the revision reversible without a data migration and
what lets it be applied before the new code serves traffic. The remaining seven
arrive with a table rather than being added to anything, and are reversed by that
table being dropped rather than column by column: four are the columns of
`webhook_events`, which revision `0001` creates, and three are the columns of
`login_attempt_slots`, which revision `0005` creates.

| # | Table.column | Type | Null | Server default | Revision operation | Model attribute | Finding | Reverse |
|---|--------------|------|:----:|----------------|--------------------|-----------------|---------|---------|
| 5.2.1 | `users.role` | `String` | `NOT NULL` | `'registered'` | `0001` `add_column` (legacy) / in `create_table` (empty) | `User.role` | H-1 | `0001` downgrade `drop_column` |
| 5.2.2 | `users.failed_login_attempts` | `Integer` | `NOT NULL` | `'0'` | as above | `User.failed_login_attempts` | M-1 | as above |
| 5.2.3 | `users.locked_until` | `DateTime` | nullable | `NULL` | as above | `User.locked_until` | M-1 | as above |
| 5.2.4 | `subscriptions.plan_id` | `String` | nullable | `NULL` | as above | `Subscription.plan_id` | H-2 | as above |
| 5.2.5 | `subscriptions.amount` | `Numeric(10, 2)` | nullable | `NULL` | as above | `Subscription.amount` | H-2 | as above |
| 5.2.6 | `subscriptions.currency` | `String` | `NOT NULL` | `'USD'` | as above | `Subscription.currency` | H-2 | as above |
| 5.2.7 | `subscriptions.paypal_order_id` | `String` | nullable | `NULL` | as above, plus the uniqueness at 5.4.3 | `Subscription.paypal_order_id` | H-3 | as above, after the uniqueness |
| 5.2.8 | `webhook_events.id` | `Integer` | `NOT NULL` | &mdash; | in `0001` `create_table` | `WebhookEvent.id` | H-4 | dropped with the table |
| 5.2.9 | `webhook_events.transmission_id` | `String` | `NOT NULL` | &mdash; | in `0001` `create_table`, with the uniqueness at 5.4.2 | `WebhookEvent.transmission_id` | H-4 | dropped with the table |
| 5.2.10 | `webhook_events.event_type` | `String` | `NOT NULL` | &mdash; | in `0001` `create_table` | `WebhookEvent.event_type` | H-4 | dropped with the table |
| 5.2.11 | `webhook_events.received_at` | `DateTime` | `NOT NULL` | `now()` | in `0001` `create_table` | `WebhookEvent.received_at` | H-4 | dropped with the table |
| 5.2.12 | `login_attempt_slots.bucket` | `Integer` | `NOT NULL` | &mdash; | in `0005` `create_table` | `LoginAttemptSlot.bucket` | M-1 | dropped with the table |
| 5.2.13 | `login_attempt_slots.attempts` | `Integer` | `NOT NULL` | `'0'` | in `0005` `create_table` | `LoginAttemptSlot.attempts` | M-1 | dropped with the table |
| 5.2.14 | `login_attempt_slots.observed_at` | `DateTime` | nullable | `NULL` | in `0005` `create_table` | `LoginAttemptSlot.observed_at` | M-1 | dropped with the table |

### 5.3 Primary and foreign keys

| # | Constraint | Columns | Target | Revision operation | Model declaration | Reverse |
|---|-----------|---------|--------|--------------------|-------------------|---------|
| 5.3.1 | PK | `users.id` | — | Precedes / `create_table` | `primary_key=True` | With the table |
| 5.3.2 | PK | `listings.id` | — | Precedes / `create_table` | `primary_key=True` | With the table |
| 5.3.3 | PK | `filters.id` | — | Precedes / `create_table` | `primary_key=True` | With the table |
| 5.3.4 | PK | `criteria.id` | — | Precedes / `create_table` | `primary_key=True` | With the table |
| 5.3.5 | PK | `zip_codes.id` | — | Precedes / `create_table` | `primary_key=True` | With the table |
| 5.3.6 | PK | `subscriptions.id` | — | Precedes / `create_table` | `primary_key=True` | With the table |
| 5.3.7 | PK | `webhook_events.id` | — | `0001` `create_table` | `primary_key=True` | With the table |
| 5.3.8 | FK | `filters.user_id` | `users.id` | Precedes / `create_table` | `ForeignKey("users.id")` | With the table |
| 5.3.9 | FK | `subscriptions.user_id` | `users.id` | Precedes / `create_table` | `ForeignKey("users.id")` | With the table |
| 5.3.10 | FK | `criteria.filter_id` | `filters.id` | Precedes / `create_table` | `ForeignKey("filters.id")` | With the table |
| 5.3.11 | FK | `zip_codes.filter_id` | `filters.id` | Precedes / `create_table` | `ForeignKey("filters.id")` | With the table |
| 5.3.12 | PK | `login_attempt_slots.bucket` | — | `0005` `create_table` | `primary_key=True, autoincrement=False` | With the table |

The four foreign keys are what fix the drop order `0001`'s downgrade uses when it
drops tables it created: `criteria` and `zip_codes` before `filters`,
`subscriptions` before `users`, and `listings`, which references nothing, at any
point among them.

### 5.4 Uniqueness

| # | Constraint | Table.column | Named | Declared by | Revision operation | Finding | Reverse |
|---|-----------|--------------|-------|-------------|--------------------|---------|---------|
| 5.4.1 | Column-level unique | `users.email` | Unnamed — the backend names it | `unique=True` on the column | Precedes / `create_table` | — | With the table |
| 5.4.2 | `uq_webhook_events_transmission_id` | `webhook_events.transmission_id` | Named | `UniqueConstraint` in `__table_args__` | `0001` `create_table` | H-4 — replay rejection | Dropped with the table |
| 5.4.3 | `uq_subscriptions_paypal_order_id` | `subscriptions.paypal_order_id` | Named | `UniqueConstraint` in `__table_args__` | `0001` `create_unique_constraint` (legacy) / in `create_table` (empty) | H-3 — capture idempotency | `0001` downgrade drops it by name, and tolerates a backend that removed it with its column |

| 5.4.4 | `uq_subscriptions_open_intent_per_plan` | `subscriptions (user_id, plan_id)`, restricted to `status IN ('pending', 'failed') AND end_date IS NULL` | Named | Partial unique `Index` in `__table_args__`, carrying both `postgresql_where` and `sqlite_where` | `0004` `create_index` | H-2, F3 — the read-then-insert race that let two concurrent requests record two open payment intents | `0004` downgrade `drop_index` |

The two named constraints are named deliberately: a reversal drops a constraint by
name, and an unnamed one is named by whatever the backend chooses. `0001`'s
downgrade looks up the uniqueness by the column it covers as well as by name, so
it also reverses cleanly on a backend that rewrites the table and takes the
constraint away with the column.

Row 5.4.4 is a unique *index* rather than a unique *constraint*, and it is recorded
here because what it guarantees is uniqueness. The distinction is load-bearing: only
an index can be partial, and the guarantee is wanted only over the window in which an
intent is still open, so a plain constraint would have forbidden a second
subscription to the same plan for all time. The three uniqueness constraints above
remain three; this is the fourth uniqueness guarantee in the delivered schema.

### 5.5 ORM relationships

No relationship is a database construct — each is a mapper-level declaration over
the foreign keys in 5.3 — so no revision operation corresponds to one. They are
listed because a reviewer checking that the models and the schema agree needs to
see that every relationship rests on a declared foreign key.

| # | Relationship | Collection | Reciprocal | Rests on |
|---|-------------|:----------:|-----------|----------|
| 5.5.1 | `User.filters` | many | `Filter.user` | 5.3.8 |
| 5.5.2 | `Filter.user` | one | `User.filters` | 5.3.8 |
| 5.5.3 | `User.subscriptions` | many | `Subscription.user` | 5.3.9 |
| 5.5.4 | `Subscription.user` | one | `User.subscriptions` | 5.3.9 |
| 5.5.5 | `Filter.criteria` | many | `Criteria.filter` | 5.3.10 |
| 5.5.6 | `Criteria.filter` | one | `Filter.criteria` | 5.3.10 |
| 5.5.7 | `Filter.zip_codes` | many | `ZipCode.filter` | 5.3.11 |
| 5.5.8 | `ZipCode.filter` | one | `Filter.zip_codes` | 5.3.11 |

`WebhookEvent` and `Listing` declare no relationship, which is correct: neither
carries a foreign key.

### 5.6 Data operations, as distinct from schema operations

Revision `0002` performs no DDL. It is separated from `0001` for exactly that
reason: the schema change and the privilege grant are independently reversible.

| # | Operation | Statement | Target | Finding | Reverse |
|---|-----------|-----------|--------|---------|---------|
| 5.6.1 | Insert the target account when absent | `INSERT ... FROM SELECT` guarded by `NOT EXISTS`, storing `role = 'registered'`, `failed_login_attempts = 0`, `hashed_password = '!locked-no-password-set'` and `created_at = CURRENT_TIMESTAMP` | `users` | H-1 | Not reversed — `0002`'s downgrade demotes, it does not delete |
| 5.6.2 | Grant the role | `UPDATE users SET role = 'admin' WHERE email = ... AND role <> 'admin'` | `users.role`, one row | H-1 | `UPDATE ... SET role = 'registered' WHERE email = ... AND role = 'admin'` |
| 5.6.3 | Assert the post-condition | The addresses holding the role, read as `SELECT email FROM users WHERE LOWER(role) = 'admin' ORDER BY email` and compared as an ordered list against exactly `['test@blitzy.com']` — not a count, so a second administrator and a single administrator at the wrong address both fail it, and a role stored in another letter case is counted rather than overlooked | `users.role` | H-1 | Re-asserted the same way, as an ordered tuple against exactly that one address, by `backend/app/core/admin_provisioning.py` before it commits |
| 5.6.4 | Store the credential | Not performed by any revision — `backend/app/core/admin_provisioning.py` performs it, as an operator step | `users.hashed_password`, one row | H-1 | Not reversed; `ADMIN_CREDENTIAL_RESET` replaces the value |

### 5.7 Reverse index — model attribute to the revision that produces it

Read from the model side. Every attribute the eleven introduced columns correspond
to, and every constraint, resolves to a revision operation; nothing in the models is
unaccounted for.

| # | Model construct | Produced by | Verified by |
|---|----------------|-------------|-------------|
| 5.7.1 | `User.role`, `User.failed_login_attempts`, `User.locked_until` | `0001` — `add_column` or `create_table` | `test_migrations.py`, `test_migration_revisions.py`, `test_postgres_migrations.py` |
| 5.7.2 | `Subscription.plan_id`, `.amount`, `.currency`, `.paypal_order_id` | `0001` — as above | as above |
| 5.7.3 | `WebhookEvent` and all 4 of its columns | `0001` `create_table` | as above, and `test_paypal_webhook.py` for the replay property |
| 5.7.4 | `uq_subscriptions_paypal_order_id` | `0001` `create_unique_constraint` or `create_table` | `test_postgres_migrations.py` — insert conflict on PostgreSQL |
| 5.7.5 | `uq_webhook_events_transmission_id` | `0001` `create_table` | as above |
| 5.7.6 | All 10 server defaults, enumerated in 5.2 | `0001` and `0005`, evaluated by the database | `test_postgres_migrations.py` — defaults read back from PostgreSQL |
| 5.7.7 | The `'admin'` value in `users.role`, one row | `0002` — data only | `test_admin_seed_migration.py`, `test_postgres_migrations.py`, `test_admin_provisioning.py` |
| 5.7.8 | The 6 tables and 34 columns that precede this work | Neither revision, on a legacy baseline; `0001` `create_table`, on an empty database | `test_migrations.py`, and the empty-database round trip in `test_postgres_migrations.py` |

### 5.8 Every column, enumerated

Sections 5.1 to 5.7 map the constructs this work changes. This subsection is the
exhaustive inventory the Rule's word *every* requires: all **48** columns with
their type, nullability, server default, key role and provenance, so the **34**
columns that precede this work are individually accounted for rather than only
counted at row 5.7.8. The **14** this work introduces cross-reference their detail
row in section 5.2.

Provenance reads "Precedes / `0001` `create_table`" for a column that exists
before this work on a legacy baseline and is created by `0001` on an empty
database - the two paths section 5.1 distinguishes. Types are as the models
declare them; a backend may widen `VARCHAR` to its own unbounded text type.

| # | Table | Column | Type | Null | Server default | Key role | Provenance |
|---|-------|--------|------|------|----------------|----------|------------|
| 5.8.1 | `users` | `id` | `INTEGER` | `NOT NULL` | &mdash; | PK | Precedes / `0001` `create_table` |
| 5.8.2 | `users` | `email` | `VARCHAR` | `NOT NULL` | &mdash; | unique | Precedes / `0001` `create_table` |
| 5.8.3 | `users` | `hashed_password` | `VARCHAR` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.4 | `users` | `created_at` | `DATETIME` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.5 | `users` | `last_login` | `DATETIME` | nullable | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.6 | `users` | `role` | `VARCHAR` | `NOT NULL` | `registered` | &mdash; | **Added by `0001`** &mdash; see 5.2.1 |
| 5.8.7 | `users` | `failed_login_attempts` | `INTEGER` | `NOT NULL` | `0` | &mdash; | **Added by `0001`** &mdash; see 5.2.2 |
| 5.8.8 | `users` | `locked_until` | `DATETIME` | nullable | `NULL` | &mdash; | **Added by `0001`** &mdash; see 5.2.3 |
| 5.8.9 | `listings` | `id` | `INTEGER` | `NOT NULL` | &mdash; | PK | Precedes / `0001` `create_table` |
| 5.8.10 | `listings` | `created_at` | `DATETIME` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.11 | `listings` | `updated_at` | `DATETIME` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.12 | `listings` | `rent` | `FLOAT` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.13 | `listings` | `broker_fee` | `FLOAT` | nullable | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.14 | `listings` | `square_footage` | `FLOAT` | nullable | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.15 | `listings` | `bedrooms` | `INTEGER` | nullable | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.16 | `listings` | `bathrooms` | `INTEGER` | nullable | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.17 | `listings` | `available_date` | `DATETIME` | nullable | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.18 | `listings` | `street_address` | `VARCHAR` | nullable | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.19 | `listings` | `zillow_url` | `VARCHAR` | nullable | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.20 | `filters` | `id` | `INTEGER` | `NOT NULL` | &mdash; | PK | Precedes / `0001` `create_table` |
| 5.8.21 | `filters` | `user_id` | `INTEGER` | `NOT NULL` | &mdash; | FK &rarr; `users.id` | Precedes / `0001` `create_table` |
| 5.8.22 | `filters` | `name` | `VARCHAR` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.23 | `filters` | `created_at` | `DATETIME` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.24 | `filters` | `last_used` | `DATETIME` | nullable | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.25 | `criteria` | `id` | `INTEGER` | `NOT NULL` | &mdash; | PK | Precedes / `0001` `create_table` |
| 5.8.26 | `criteria` | `filter_id` | `INTEGER` | `NOT NULL` | &mdash; | FK &rarr; `filters.id` | Precedes / `0001` `create_table` |
| 5.8.27 | `criteria` | `field` | `VARCHAR` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.28 | `criteria` | `operator` | `VARCHAR` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.29 | `criteria` | `value` | `VARCHAR` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.30 | `zip_codes` | `id` | `INTEGER` | `NOT NULL` | &mdash; | PK | Precedes / `0001` `create_table` |
| 5.8.31 | `zip_codes` | `filter_id` | `INTEGER` | `NOT NULL` | &mdash; | FK &rarr; `filters.id` | Precedes / `0001` `create_table` |
| 5.8.32 | `zip_codes` | `code` | `VARCHAR` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.33 | `subscriptions` | `id` | `INTEGER` | `NOT NULL` | &mdash; | PK | Precedes / `0001` `create_table` |
| 5.8.34 | `subscriptions` | `user_id` | `INTEGER` | `NOT NULL` | &mdash; | FK &rarr; `users.id` | Precedes / `0001` `create_table` |
| 5.8.35 | `subscriptions` | `start_date` | `DATETIME` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.36 | `subscriptions` | `end_date` | `DATETIME` | nullable | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.37 | `subscriptions` | `status` | `VARCHAR` | `NOT NULL` | &mdash; | &mdash; | Precedes / `0001` `create_table` |
| 5.8.38 | `subscriptions` | `plan_id` | `VARCHAR` | nullable | `NULL` | &mdash; | **Added by `0001`** &mdash; see 5.2.4 |
| 5.8.39 | `subscriptions` | `amount` | `NUMERIC(10, 2)` | nullable | `NULL` | &mdash; | **Added by `0001`** &mdash; see 5.2.5 |
| 5.8.40 | `subscriptions` | `currency` | `VARCHAR` | `NOT NULL` | `USD` | &mdash; | **Added by `0001`** &mdash; see 5.2.6 |
| 5.8.41 | `subscriptions` | `paypal_order_id` | `VARCHAR` | nullable | `NULL` | &mdash; | **Added by `0001`** &mdash; see 5.2.7 |
| 5.8.42 | `webhook_events` | `id` | `INTEGER` | `NOT NULL` | &mdash; | PK | **Introduced with the table by `0001`** &mdash; see 5.2.8 |
| 5.8.43 | `webhook_events` | `transmission_id` | `VARCHAR` | `NOT NULL` | &mdash; | unique | **Introduced with the table by `0001`** &mdash; see 5.2.9 |
| 5.8.44 | `webhook_events` | `event_type` | `VARCHAR` | `NOT NULL` | &mdash; | &mdash; | **Introduced with the table by `0001`** &mdash; see 5.2.10 |
| 5.8.45 | `webhook_events` | `received_at` | `DATETIME` | `NOT NULL` | `now()` | &mdash; | **Introduced with the table by `0001`** &mdash; see 5.2.11 |
| 5.8.46 | `login_attempt_slots` | `bucket` | `INTEGER` | `NOT NULL` | &mdash; | PK | **Introduced with the table by `0005`** &mdash; see 5.2.12 |
| 5.8.47 | `login_attempt_slots` | `attempts` | `INTEGER` | `NOT NULL` | `0` | &mdash; | **Introduced with the table by `0005`** &mdash; see 5.2.13 |
| 5.8.48 | `login_attempt_slots` | `observed_at` | `DATETIME` | nullable | `NULL` | &mdash; | **Introduced with the table by `0005`** &mdash; see 5.2.14 |

## 6. Delivered targets the plan does not contain

Sections 1 to 4 map the plan's 68 entries. Rule 1 asks for coverage of the delivered
implementation, so this section reaches the paths delivered beyond that mapping from the
finding side, which is the direction sections 2.9 and 4.1 do not run in. Each is therefore
reachable three ways: by its path forward in section 2.9, by its path backward in section
4.1 or 4.3, and by the finding or Rule it serves here.

### 6.1 What this section counts, and what it does not

Measured with `git diff --name-status a26f7fb HEAD` — the last commit before this
remediation — against a clean working tree. This restates section 2.10's measurement from
the plan's side; the two are one figure, not two.

| Quantity | Count |
|---|---|
| Paths the plan's mapping marks CREATE or UPDATE | **59** |
| — of those, delivered | **59** |
| — of those, still pending | **0** |
| Paths beyond the plan that sections 6.2 to 6.4 enumerate | **27** |
| — of those, created | **26** |
| — of those, a mode change on a path the plan marks REFERENCE | **1** |
| Paths beyond the plan delivered by the rounds after them (§2.9's second table) | **61** |
| — of those, withdrawn by the manifest consolidation | **17** |
| **Delivered paths in total** | **130** |
| — created | **100** |
| — modified | **30** |
| Paths the plan marks REFERENCE and that are unmodified | **8** |

`59 + 27 + 61 - 17 = 130`. `8 + 1 = 9`, the plan's REFERENCE count, so every reference
entry is accounted for as either unmodified or mode-changed. `backend/app/api/router.py`
is the tenth reference-mode row the plan renders and the plan's total does not count; it
is unmodified, which is what section 2.1 carries it to prove, and section 2.8 records the
treatment.

The subtraction is the only unusual term and it is not a recount: the 17 paths were
delivered, then withdrawn by the consolidation recorded at `infrastructure/k8s/README.md`,
so they are indexed with mode DELETE and are not in the tree the 130 measures.

**This supersedes the snapshot at `docs/security/DECISION_LOG.md` §23.1**, which recorded
58 changed paths, 47 planned-and-delivered, 11 unplanned and 12 pending. That was a
per-round measurement and was accurate when taken; the figures above are the whole of the
work. It also supersedes the **86** this table published in an earlier revision, which
counted the delivered set before the manifest consolidation and the rounds after it; the
snapshot register in section 2.10 records that figure and the two others beside it.

### 6.2 Created beyond the plan

Twenty-six paths. Each serves a finding the plan maps, or a Rule, or is named as a
byproduct.

| # | Delivered path | Serves | Reached forward from |
|---|---|---|---|
| 1 | `backend/.dockerignore` | INFRA-3 | The build context the backend image copies is `backend/`, so the exclusions have to sit there as well as at the root |
| 2 | `frontend/.dockerignore` | INFRA-3 | The same property for the frontend build context |
| 3 | `setup.cfg` | INFRA-2, INFRA-5 | One `flake8`, `pytest` and coverage configuration for both documented working directories |
| 4 | `backend/app/core/rate_limit.py` | API4 resource consumption, alongside `main.py` | The bounded in-memory rate-limit store the credential endpoints use |
| 5 | `backend/tests/support.py` | The whole test suite | The shared settings, addresses and helpers `conftest.py` and every module draw on |
| 6 | `frontend/package-lock.json` | None — byproduct | Recorded at `docs/security/DECISION_LOG.md` row 23.2.3, which also records why deleting it was declined. Its presence closes the reported item that no frontend lock file existed |
| 7 | `backend/tests/security/test_token_hardening.py` | C-2, H-7 | Token minting and claim enforcement beyond the planned module's cases |
| 8 | `backend/tests/security/test_authorization.py` | H-1 | The centralized dependency's own behaviour, separate from the route grid |
| 9 | `backend/tests/security/test_login_throttling_and_timing.py` | M-1 | Response uniformity and throttle behaviour |
| 10 | `backend/tests/security/test_rate_limit_store.py` | API4 | The bounded store of entry 4 |
| 11 | `backend/tests/security/test_request_bounds_and_refusals.py` | H-5, H-6 | Pagination bounds, body caps and refusal shapes |
| 12 | `backend/tests/security/test_payment_lifecycle.py` | C-3, H-2, H-3, H-4 | The order and capture lifecycle end to end |
| 13 | `backend/tests/security/test_application_surface.py` | M-2, M-3 | Headers, origins, hosts, health and the exception handlers |
| 14 | `backend/tests/security/test_settings_and_redaction.py` | C-1, M-4 | Settings validation and the redacting logger |
| 15 | `backend/tests/security/test_migrations.py` | H-1 | The additive revision's schema effect |
| 16 | `backend/tests/security/test_migration_gate.py` | H-1 | That the code refuses a schema behind it |
| 17 | `backend/tests/security/test_migration_revisions.py` | H-1 | Revision ordering and independent reversal |
| 18 | `backend/tests/security/test_revision_contracts.py` | H-1 | The server defaults each added column carries |
| 19 | `backend/tests/security/test_admin_seed_migration.py` | H-1 | The sole-administrator post-condition, asserted as the ordered address list rather than as a count |
| 20 | `backend/tests/security/test_setup_script.py` | C-1 | That the script declares each read-only name once |
| 21 | `backend/tests/security/test_setup_script_bootstrap.py` | C-1 | That its bootstrap executes cleanly |
| 22 | `backend/tests/security/test_deployment_contract.py` | C-4, INFRA-3 | The Compose document, the image contexts and the configuration template |
| 23 | `backend/tests/security/test_terraform_contract.py` | INFRA-1 | The node role and scope, the private-endpoint enforcement, the shared-VPC invariant, the authoritative function policy and the per-secret grants |
| 24 | `backend/tests/security/test_release_contract.py` | INFRA-2, INFRA-4 | The pipeline's job graph and gates, the build commands, and the deployment script's ordering and function flags |
| 25 | `backend/tests/security/test_residual_risk_guards.py` | The residual-risk acceptance | The syntax-tree reachability assertion and the suppression-to-register mapping |
| 26 | `backend/tests/security/test_security_documentation.py` | Rules 1 and 3 | Document presence, link resolution and the credential inventory's agreement across three documents |

### 6.3 A mode change on a path the plan marks REFERENCE

One path. It is recorded here because a reference-mode row that was in fact modified is
precisely the kind of gap this section exists to close.

| Delivered path | Planned mode | Delivered mode | What changed | Serves |
|---|---|---|---|---|
| `infrastructure/docker/Dockerfile.frontend` | REFERENCE | UPDATE | Two `ARG` declarations and the matching `ENV` export for `REACT_APP_API_BASE_URL` and `REACT_APP_PAYPAL_CLIENT_ID`, so the two non-secret build arguments the Compose file and the deployment workflow pass reach the built bundle | C-4's requirement that no build argument carry a secret, and the frontend build seam recorded at `docs/security/DECISION_LOG.md` §29 |

The other eight REFERENCE paths — `frontend/src/services/auth.ts`,
`frontend/src/services/paypal.ts`, `frontend/src/schema/subscription.ts`,
`frontend/src/utils/validators.ts`, `frontend/package.json`,
`documentation/Technical Specifications.md`,
`documentation/Software Requirements Specifications (SRS).md` and
`documentation/Software Project Proposal.md` — are unmodified, and
`backend/app/api/router.py` is unmodified as well. Nothing under `frontend/src/**` was
edited.

### 6.4 Twenty-seven of those paths reached from the finding side

Sections 6.2 and 6.3 are reached from the path side. This table reaches the identical
twenty-seven from the finding, Rule or instruction side, so those paths are bidirectional
on the same terms as sections 1 and 4. The paths delivered by the rounds after this one are
reached forward by section 2.9's second table and backward by section 4.3.

| Reached from | Delivered paths beyond the plan that serve it |
|---|---|
| **C-1** | `backend/tests/security/test_settings_and_redaction.py`, `backend/tests/security/test_setup_script.py`, `backend/tests/security/test_setup_script_bootstrap.py` |
| **C-2**, **H-7** | `backend/tests/security/test_token_hardening.py` |
| **C-3**, **H-2**, **H-3**, **H-4** | `backend/tests/security/test_payment_lifecycle.py` |
| **C-4** | `backend/tests/security/test_deployment_contract.py`, `infrastructure/docker/Dockerfile.frontend` |
| **H-1** | `backend/tests/security/test_authorization.py`, `backend/tests/security/test_migrations.py`, `backend/tests/security/test_migration_gate.py`, `backend/tests/security/test_migration_revisions.py`, `backend/tests/security/test_revision_contracts.py`, `backend/tests/security/test_admin_seed_migration.py` |
| **H-5**, **H-6** | `backend/tests/security/test_request_bounds_and_refusals.py` |
| **M-1** | `backend/tests/security/test_login_throttling_and_timing.py` |
| **M-2**, **M-3** | `backend/tests/security/test_application_surface.py` |
| **M-4** | `backend/tests/security/test_settings_and_redaction.py` |
| **INFRA-1** | `backend/tests/security/test_terraform_contract.py` |
| **INFRA-2** | `setup.cfg`, `backend/tests/security/test_release_contract.py` |
| **INFRA-3** | `backend/.dockerignore`, `frontend/.dockerignore`, `backend/tests/security/test_deployment_contract.py` |
| **INFRA-4** | `backend/tests/security/test_release_contract.py` |
| **INFRA-5** | `setup.cfg` |
| The plan's rate-limit requirement on the credential endpoints, carried in its `backend/app/main.py` row (API4 in its OWASP mapping) | `backend/app/core/rate_limit.py`, `backend/tests/security/test_rate_limit_store.py` |
| The accepted-residual-risk instruction | `backend/tests/security/test_residual_risk_guards.py` |
| Rules 1 and 3 | `backend/tests/security/test_security_documentation.py` |
| No finding — suite infrastructure and one byproduct | `backend/tests/support.py`, `frontend/package-lock.json` |

The union of the right-hand column is **27** distinct paths, the same 27 that sections 6.2
and 6.3 enumerate, and a subset of the 64 beyond-plan paths section 2.10 counts. Two carry no finding identifier and are recorded as such rather than
attached to one they do not serve: `backend/tests/support.py` is shared suite
infrastructure, and `frontend/package-lock.json` is the byproduct recorded at
`docs/security/DECISION_LOG.md` row 23.2.3.

### 6.5 Constructs removed by the infrastructure and release-path round

Section 3 maps the constructs the dependency replacements and the findings turned on.
These are the constructs this round removed or replaced, in the same old-to-new form.

| Old construct | Location | New construct | Belongs to |
|---|---|---|---|
| `resource "google_cloudfunctions_function_iam_member" "invoker"` | `infrastructure/terraform/main.tf` | `resource "google_cloudfunctions_function_iam_binding" "invoker"`, the authoritative form for one role: it declares the whole membership of `roles/cloudfunctions.invoker` rather than adding to it. No policy resource and no `_iam_member` resource for that role exists in the configuration | The Cloud Function invoker restriction |
| `name = "function-test"` and `entry_point = "hello_world"` as literals | `infrastructure/terraform/main.tf` | `var.cloud_function_name` and `var.cloud_function_entry_point`, with `var.cloud_function_source_archive_object` for the archive | Function identity shared with `scripts/deploy.sh` |
| `oauth_scopes = ["…/logging.write", "…/monitoring"]` | `infrastructure/terraform/main.tf` | `var.gke_node_oauth_scopes`, defaulting to the `cloud-platform` scope | GKE node identity |
| `gcloud functions deploy function-name --source=./functions` | `scripts/deploy.sh` | `gcloud functions deploy "$CLOUD_FUNCTION_NAME" --source="$CLOUD_FUNCTION_SOURCE_ARCHIVE" … --no-allow-unauthenticated`, preceded by an existence check on the archive | Function identity and invoker restriction |
| `docker build -t … .` at the repository root | `scripts/deploy.sh` | `docker build --file infrastructure/docker/Dockerfile.<image> … <context>` per workload, with one `--build-arg` per name the `WORKLOAD_BUILD_ARGUMENTS` table declares for that image | Deployment correctness; the frontend build values |
| No frontend `--build-arg` anywhere in the script, so the browser bundle was built with neither declared `ARG` | `scripts/deploy.sh` | `WORKLOAD_BUILD_ARGUMENTS` declaring `REACT_APP_API_BASE_URL` and `REACT_APP_PAYPAL_CLIENT_ID` for the frontend image, `read_build_arguments()` deriving the client identifier from the same `PAYPAL_CLIENT_ID` the manifests render and refusing an empty value, and `publish_images()` passing each as a separate word | The frontend build values |
| `kubectl set image` before the Alembic upgrade | `scripts/deploy.sh` | A one-shot migration pod on the new image, gated on its phase, and only then the rollout. The rollout is no longer `kubectl set image` either: `deploy_workloads` applies the rendered manifests, which carry this run's digests, so `apply_database_migrations` precedes `deploy_workloads` in `main` and the command the old construct names appears in neither release path | Migration-before-traffic |
| `npm run lint` | `.github/workflows/ci.yml` | Removed; `frontend/package.json` declares no such script | Pipeline reachability |
| An empty `run:` under "Run integration tests" | `.github/workflows/ci.yml` | A PostgreSQL service, `alembic upgrade head`, an administrator-count assertion and six live probes | The integration gate |
| `--include=*.py backend/` | `.github/workflows/ci.yml` | `--include=*.py backend/app/`, with `backend/tests/security/test_residual_risk_guards.py` as the semantic layer | Residual-advisory reachability |
| `jobs.verify` duplicating three gates | `.github/workflows/cd.yml` | Four jobs in one chain, each waiting on the one before it: `preflight`, then `verify` with `uses: ./.github/workflows/ci.yml` and `needs: preflight`, then `build` with `needs: verify`, then `deploy` with `needs: build`. So nothing is published until the whole verification workflow passes, and nothing is verified until the preflight has established that the triggering run is trusted | Deployment gating |
| `GKE_ZONE` from `secrets.GKE_CLUSTER_ZONE`, used as `--zone` | `.github/workflows/cd.yml` | `GKE_LOCATION` from `secrets.GKE_CLUSTER_REGION`, used as `--region` with `--internal-ip` | Reaching a regional private control plane |
| `docker build … ./frontend` and `… ./backend` | `.github/workflows/cd.yml` | `docker build -f infrastructure/docker/Dockerfile.frontend … frontend` with both `--build-arg` values, and the backend equivalent | Build integration |
| The proxy service with no address-type selection | `infrastructure/docker/docker-compose.yml` | `-ip_address_types=PRIVATE` beside `-instances=…`, on the v1 `gce-proxy:1.19.1` image the baseline pins. The image tag is left as the baseline set it: raising it is one of the ten items held for confirmation, and row 91.1.2 records the revert that restored it | Cloud SQL private connectivity |
| `--build-arg` values read from `secrets.REACT_APP_API_BASE_URL` and `secrets.PAYPAL_CLIENT_ID`, while the manifest rendering read `vars.PAYPAL_CLIENT_ID` and `README.md` documented both as repository variables — so under the documented configuration the bundle was built with an empty client identifier | `.github/workflows/cd.yml` | Workflow-level `env` resolving `REACT_APP_API_BASE_URL` from `vars.REACT_APP_API_BASE_URL` and `REACT_APP_PAYPAL_CLIENT_ID` from the same `vars.PAYPAL_CLIENT_ID` expression the manifest rendering reads, a preflight step refusing an empty value before anything is built, and a re-check immediately before `docker build` | The frontend build values |
| The `# HUMAN ASSISTANCE NEEDED` block | `infrastructure/terraform/main.tf` | A six-item prerequisites list and a four-item open-risks list | Completeness |

## 7. Completeness statement

Rule 1 requires 100% coverage with no gaps, and **coverage of a finding means an
assertion that reaches the control, not a filled cell in a table.** An earlier version of
this section substantiated completeness by counting — 20 findings mapped in both
directions, 68 entries reconciling to the same total, no empty cells — and those counts
were true while being the wrong evidence. A matrix can be complete in that sense and
still map a finding to a test that cannot fail when the control regresses; the structural
counts are retained in section 2.8, where they belong as a reconciliation against the
plan, and are no longer offered here as proof of verification.

## 8. Verification status

Rule 1 requires 100% coverage with no gaps, and **coverage of a finding means an
assertion that reaches the control, not a filled cell in a table.** An earlier version of
this section substantiated completeness by counting — 20 findings mapped in both
directions, 68 entries reconciling to the same total, no empty cells — and those counts
were true while being the wrong evidence. A matrix can be complete in that sense and
still map a finding to a test that cannot fail when the control regresses; the structural
counts are retained in section 2.8, where they belong as a reconciliation against the
plan, and are no longer offered here as proof of verification.

What follows is the semantic status of each of the 20 findings. **PASS** means an
automated assertion exercises the control and fails when it is removed — proven by
perturbation, not by inspection. **PARTIAL** means the code-level control is asserted that
way but something the code cannot carry remains outstanding, and the outstanding part is
named. **FAIL** would mean no assertion reaches the control; there are none.

| Finding | Status | Assertion that reaches the control | What removing the control breaks | Outstanding |
|---|---|---|---|---|
| **C-1** | PASS | `test_config_validation.py` startup cases; `test_the_setup_step_writes_a_strong_generated_signing_key[openssl\|interpreter]` and `test_the_generated_signing_key_is_not_the_shipped_placeholder` execute the generator in an isolated root | A short or placeholder key stops startup; a generator emitting a fixed placeholder-bearing key fails the setup cases | — |
| **C-2** | PASS | `test_jwt_hardening.py` — `alg:none`, algorithm confusion, wrong key, wrong audience, wrong issuer, every missing required claim | Widening the accepted algorithm list, or reading it from the token header, fails these | — |
| **C-3** | PASS | `test_config_validation.py` production-versus-sandbox guard; the mode derives from validated configuration | A production environment paired with sandbox credentials fails at startup | — |
| **C-4** | **PARTIAL** | `check_secret_policy.sh` in the pipeline — no secret-bearing path tracked, no tracked file carrying a real credential, all 17 reintroduction paths ignored; `test_the_gate_carries_the_secret_and_ignore_policy_check` asserts the gate is wired | Planting a credential, or weakening the ignore rules, fails the gate | **Rotation is outstanding, and nothing in this repository can confirm whether the exposed values still authenticate.** That is an issuer-side fact, and this work has no access to the database server or the cloud console to establish it; what is checkable here is that the values were removed from the tree, that they remain in this repository's history, and that removal from a tree does not remove a value from history or from any existing clone. Each must therefore be treated as compromised. `CREDENTIAL_ROTATION.md` sequences revoke → rotate → delete from history → review access, and the operation is irreversible and is not performed here. The pipeline gate prevents recurrence; it cannot un-leak what was leaked. |
| **H-1** | PASS | `test_rbac_matrix.py` — 9 routes × 5 principals, deny by default; the role is read from the database row, never from the token claim | Any route losing its role requirement fails its row | — |
| **H-2** | PASS | `test_subscription_tampering.py` — a submitted amount never reaches the row, client dates never govern entitlement, an unknown plan is refused | Reinstating a client-supplied amount or date fails these | — |
| **H-3** | PASS | `test_subscription_tampering.py` capture-ownership cases — capture of another user's order is refused with no state change | Removing the server-side ownership lookup fails these | — |
| **H-4** | PASS | `test_paypal_webhook.py` — tampered signature, non-allowlisted certificate host rejected before the URL is used, replayed transmission identifier, missing header; `test_the_unique_index_makes_the_repeat_wait_on_postgres` proves the repeat is blocked by the real index | Removing the `UniqueConstraint` fails the PostgreSQL contention cases; removing host allowlisting fails the certificate case | — |
| **H-5** | PASS | `test_request_bounds_and_refusals.py` — both paged reads refuse an oversized limit behaviourally, not only in the published schema | Removing `le=settings.MAX_PAGE_SIZE` fails four request cases, not just the schema one | — |
| **H-6** | PASS | `test_mass_assignment.py` — extra body fields set no column outside the allowlist; a registration body carrying a role still yields `registered` | Reintroducing dictionary unpacking fails these | — |
| **H-7** | PASS | `test_jwt_hardening.py` — a legacy email-subject token is rejected; a valid token naming a deleted user answers 401, indistinguishably from an invalid one | Minting an email subject, or returning 404 for a missing user, fails these | — |
| **M-1** | PASS | `TestRefusalBranchesDoTheSameWork` counts one credential check, two comparisons and one budget equalisation per refusal branch, and asserts a single distinct refusal triple; `TestRefusalBranchesTakeTheSameTime` measures the same property end to end and is marked `timing` | Reintroducing the unknown-address short-circuit fails exactly the unknown branch, with no clock read | — |
| **M-2** | PASS | `test_application_surface.py` asserts every header in `SECURITY_HEADERS`, including on refused and throttled responses | Dropping a header fails these | — |
| **M-3** | **PARTIAL** | `TestCrossOriginPolicy` — the installed middleware keywords carry no wildcard, and real allowed and disallowed preflights are negotiated | A wildcard method, header or origin fails 4–5 cases; removing the middleware fails the class | **Per-environment configuration is an operational input.** `ALLOWED_ORIGINS` and `ALLOWED_HOSTS` must name the real origins of each deployment; the assertions prove the policy is explicit and enforced, not that a given deployment's list is the right one. The failure mode is a refused request rather than a silent gap. |
| **M-4** | PASS | `test_settings_and_redaction.py` redaction cases; `test_services.py` asserts the provider key travels in a header and appears in no URL or record; `test_no_record_carries_the_injected_user_data` asserts both PII sentinels are absent from every record field | Restoring the exception message to the 500 record fails the PII case with the leak shown | — |
| **INFRA-1** | **PARTIAL** | `terraform validate`; `test_the_control_plane_keeps_no_public_endpoint`, `test_the_control_plane_stays_private_and_is_still_reachable`, `test_at_least_one_authorized_network_is_required`, `test_the_node_pool_carries_the_scope_its_image_pulls_need`, `test_the_node_identity_may_read_the_registry_it_pulls_from`, `test_the_node_identity_holds_no_project_wide_storage_read` | Making the endpoint public, defaulting the authorized networks to none, or narrowing the node scope fails these. The first case asserts only the two IP-endpoint declarations, so the claim that no public path remains rests on the second, which reads the *value* of `gke_dns_endpoint_external_traffic` and requires the declared default to be `false` — the DNS-based endpoint authorizes by `container.clusters.connect` rather than by source address, so a default of `true` would have admitted a caller outside the VPC unless a deployment opted out. The last case refuses `roles/storage.objectViewer` on the node identity | **A declaration is asserted, not a running deployment.** No `terraform apply` runs in this repository, so Secret Manager resources, private IP, SSL enforcement, backups and deletion protection are verified as declarations. Confirming the applied state is a deployment-time review step. |
| **INFRA-2** | **PARTIAL** | The pipeline's own gates plus 36 assertions over them — no undeclared npm script invoked, a supported Node major, the database service and its major, the dialect cases reachable and unskippable, both advisory registers separate, no deferred work marker, every step carrying a command | Reinstating either frontend gate, the placeholder step, a wrong Node major or a merged advisory step fails a named case | **Federated identity is asserted as a declaration.** The deployment workflow requests an identity token and uses keyless authentication; that the identity provider is correctly bound in the cloud project cannot be verified from this repository. |
| **INFRA-3** | PASS | `test_the_backend_image_ends_as_the_unprivileged_user`, `test_the_backend_image_leaves_the_application_tree_unwritable`, `test_the_ownership_change_precedes_the_user_switch`, and 32 build-context exclusion cases run over both contexts the image is built from with the context's own matching rules | `USER root`, a writable `/app`, or removing an ignore pattern each fail their cases | — |
| **INFRA-4** | **PARTIAL** | `test_the_deploy_script_stops_at_the_first_failure`, the real definitions and Deployments, `test_the_schema_is_migrated_before_anything_new_serves`, `test_a_failed_migration_stops_the_deployment`, `test_no_deployment_publishes_the_function_to_everyone` | Migrating after the rollout, or reinstating the public-invocation flag, fails these | **The script is asserted statically.** It requires a cluster and a container engine, neither of which exists on the verification host, so its behaviour is asserted against the declaration. The Cloud Function step is additionally inert here because the repository carries no function source. |
| **INFRA-5** | PASS | `pip-audit -r backend/requirements.txt` and `-r backend/requirements-dev.txt` as separate pipeline steps; `test_the_two_advisory_registers_are_suppressed_separately`; the `python-multipart` absence guard and the reachability guard | Merging the audit steps, or reintroducing the omitted package, fails a named case | — |

**Plan entries, both directions.** Sections 2.1 to 2.7 enumerate the plan's **68**
transformation entries forward by target path, and the reverse index of section 4 reaches
the same 68 backward. The mode subtotals reconcile as
**30 CREATE + 29 UPDATE + 0 DELETE + 9 REFERENCE = 68**, which is the total the frozen
plan itself publishes, and the group subtotals of section 2.8 add to the same figure:
`10 + 10 + 7 + 12 + 12 + 8 + 9 = 68`. Both directions additionally render
`backend/app/api/router.py`, the reference-mode row the plan carries inside its
application-core group rather than in its read-only-references table, so section 4 holds
**69** rows for those 68 entries; section 2.8 states why that row is rendered and not
counted. The CREATE and UPDATE columns alone give the **59** planned changed paths, all of
which were delivered.

Every figure in that paragraph describes **the plan**, which is frozen, and none of them
moves because of the correction in section 2.7. What that correction changes is a claim
about **delivery**, and the two are stated separately here so neither is read as the other:

| Quantity | Count | What it counts |
|---|---|---|
| Plan entries | **68** | Sections 2.1–2.7, every mode, as the frozen plan totals them |
| Plan changed paths | **59** | CREATE + UPDATE only |
| Plan reference paths rendered | **10** | Section 2.7's nine, plus the row section 2.1 carries and the total does not count |
| — of those, delivered unmodified | **9** | Verifiable by absence from the changed set: section 2.7's eight, plus `backend/app/api/router.py` |
| — of those, modified in delivery | **1** | `infrastructure/docker/Dockerfile.frontend` |
| Delivered changed paths, plan-derived | **60** | The 59 above plus that one path |
| Contextual rows counted in no total | **1** | `backend/app/api/router.py`, rendered in section 2.1 |

**Verifiable by absence, precisely.** Nine paths are absent from the changed set and can
be verified that way. Eight of them are section 2.7's, and the ninth is
`backend/app/api/router.py`, the contextual row section 2.1 renders: its being
unedited is the evidence that the four router prefixes were preserved, so it is claimed
here rather than merely rendered. The eight are `frontend/src/services/auth.ts`,
`frontend/src/services/paypal.ts`,
`frontend/src/schema/subscription.ts`, `frontend/src/utils/validators.ts`,
`frontend/package.json`, `documentation/Technical Specifications.md`,
`documentation/Software Requirements Specifications (SRS).md` and
`documentation/Software Project Proposal.md`. The ninth is not, and section 2.7 says why.
Naming the eight rather than writing "all nine" is what keeps the claim checkable: a
reader can run `git log --follow` against each of them and against the ninth, and get the
answer this document predicts in all nine cases.

**Constructs.** Section 3 maps every replaced construct to its replacement across the three
dependency refactors and the two migration revisions that supersede schema creation at
import time, with each baseline location read back from revision `a26f7fb`.

**Delivered paths, both directions.** Section 2.9 enumerates the **86** paths delivery
carries or carried that the plan does not, forward by target path; sections 4.1 and 4.3
contain the same 87 backward — **26** and **61** across their two tables. Seventeen of the
86 were withdrawn by the manifest consolidation and the provider-pinning revert and are
indexed with their mode or withdrawal stated, leaving **69** in the current tree. Together
with the 59 delivered planned changes and the one plan-marked read-only path that was
modified, the delivered total is **130**, reconciled in section 2.10. Both axes therefore cover the tree as delivered and not only the plan as
written, which is the property an earlier revision of this file did not have.

**Schema constructs, both directions.** Section 5 maps the schema construct by construct.
Forward, sections 5.1 to 5.6 account for **8** tables, **14** introduced columns, **8**
primary keys, **4** foreign keys, **3** uniqueness constraints, **8** relationships and
**4** data operations, naming for each the revision operation that produces it and the
reverse operation that removes it. Backward, section 5.7 reaches every one of those from
the model side. Section 5.8 is the exhaustive column inventory: all **48** columns —
**33** `NOT NULL` plus **15** nullable, with **10** server defaults — each with its type,
key role and provenance, so the **34** that precede this work are individually listed and
not merely counted. Of the **14** introduced, the **7** appended to a pre-existing table
each carry a server default, which is the countable form of the reversibility property;
the other **7** arrive with `webhook_events` or `login_attempt_slots` and are reversed by
that table being dropped.

Every figure in this paragraph was read back from `Base.metadata` and from the revision
files rather than transcribed, and the section-5.8 rows were generated from the models.
`backend/tests/security/test_documentation_accuracy_contract.py` re-derives them from the
code and compares them against this file — the totals paragraph of section 5, the
provenance split beneath it, the enumeration in 5.2, the enumeration in 5.8 with each
row's provenance, and this paragraph — so the schema, section 5 and this summary cannot
silently diverge.

**Fifteen findings are PASS and five are PARTIAL, and none of the five is partial
because an assertion is missing.** In every case the code-level control is asserted and
proven by perturbation, and what remains is a class of thing a test in this repository
cannot reach: an irreversible operational rotation, a per-environment configuration
value, an applied cloud state, an identity binding in a cloud project, and a script that
needs a cluster. Those five classes correspond one-to-one to the five PARTIAL rows above
— C-4, M-3, INFRA-1, INFRA-2 and INFRA-4. Each is named above rather than absorbed, and
each appears in the resolution report's open items.

**On "no empty cells".** Every row in every table above does carry a value in every
column, and where a path serves no finding — the four `docs/security/` artefacts,
`docs/review/CRITICAL_DECISIONS.md`, `blitzy-deck/executive-summary.html` and
`SECURITY.md` — its governing Rule is recorded in place of a finding identifier and a
review activity in place of an automated test. That is a statement about the tables'
shape and is recorded as such. It is not evidence that a control is verified, and it is
no longer presented as any part of the completeness claim.

**Delivered targets, both directions.** Section 6 enumerates the delivered paths the
plan's mapping does not contain, so the inventory covers what was delivered and not only
what was planned. Sections 6.2 and 6.3 reach the round's own 27 from the path side and
section 6.4 reaches the same 27 from the finding, Rule or instruction side, which is what
makes the two directions reconcile rather than merely coexist; the rounds after it are
carried in section 2.9's second table and in section 4.3 on the same basis.
`59 + 27 + 61 - 17 = 130` delivered paths, the one identity this document publishes,
measured against the tree in [section 6.1](#61-what-this-section-counts-and-what-it-does-not). Section 6.5 adds the
constructs this work's infrastructure and release-path round removed or replaced, in the
same old-to-new form section 3 uses.

**Three paths that previously carried a review activity now carry an automated one.**
`scripts/deploy.sh`, `.github/workflows/cd.yml` and the Terraform files were mapped to
review verification because nothing executed against them. `backend/tests/security/test_pipeline_contract.py`
now does, so their rows in sections 1, 4, 4.1 and 4.2 name it. An earlier revision of this file
stated that no automated coverage targeted `scripts/deploy.sh`; that statement is withdrawn
here rather than edited away, because it was true when written.

## 9. The delivery-surface review — fifteen findings, both directions

The sections above map the plan's own finding register. This section maps a later
review of the delivery surface, whose fifteen findings are numbered separately
because they are not the plan's: M1 to M11 and m1 to m4. Two of them concern this
document and one concerns `docs/security/DECISION_LOG.md`, which is why this set
is recorded here rather than only in that log's per-round form —
row 35.9.2 there explains the change of practice.

Every row names the file the root cause was fixed in and the test that verifies
it. Where a finding's subject is a file no test can execute — a workflow, a
Terraform module, a Markdown document — the verifying test is a contract case
that reads the file, and section 35.6 of the decision log records why those
contract modules were added at all.

| # | Finding, as behaviour | Root cause fixed in | Verified by |
|---|---|---|---|
| M1 | The deployment script built, targeted and deployed three paths that do not exist, so it had never completed | `scripts/deploy.sh` | `bash -n`; the two preflight refusals executed; `test_deployment_contract.py`, `test_setup_script.py`, `test_setup_script_bootstrap.py` |
| M2 | The migration ran after the rollout, inside a serving pod, from that pod's image | `scripts/deploy.sh` | The `jq` overrides transformation executed against a captured Deployment; `test_pipeline_contract.py::TestTheSchemaIsMigratedBeforeTheRollout` for the workflow's equivalent |
| M3 | Both image builds omitted `-f` where no context has a default `Dockerfile`, and the cluster was addressed by zone though Terraform declares it regional | `.github/workflows/cd.yml` | `test_pipeline_contract.py::TestEveryImageBuildNamesItsDockerfile`, `::TestEveryClusterAddressIsRegional` |
| M4 | Deployment was gated on a security subset, with no full suite, no integration check and no dependency on verification | `.github/workflows/cd.yml`, `.github/workflows/ci.yml` | `test_pipeline_contract.py::TestDeploymentIsGatedOnFullVerification` |
| M5 | A step invoked an npm script the manifest does not declare, ending the job before the dependency, static-analysis, guard and security gates ran | `.github/workflows/ci.yml` | `test_pipeline_contract.py::TestNoCheckCanSuppressAnother`, `::TestEveryInvokedCommandExists` |
| M6 | The public readiness route opened a session and read the database on every anonymous call, unbounded | `backend/app/main.py`, `backend/app/core/config.py`, `backend/app/db/database.py` | `test_application_surface.py::TestTheReadinessProbeIsBounded`; `test_rbac_matrix.py::test_the_readiness_route_is_bounded_for_every_principal` |
| M7 | The decision log deferred the delivery surface to another checkpoint and recorded no decision for six delivery choices | `docs/security/DECISION_LOG.md` §35 | The section itself, its three withdrawals in §35.9, and `test_documentation_contract.py` for its checkable claims |
| M8 | This document recorded a modified file as unmodified, and its counts did not distinguish plan from delivery | `docs/security/TRACEABILITY_MATRIX.md` §2.7, §4, §5 | `git log --follow` on the path, reporting commit `25b378b` and nine insertions; `test_deployment_contract.py`'s build-argument case |
| M9 | Ten content slides exceeded the body-text cap, and three claims overstated what was delivered | `blitzy-deck/executive-summary.html` | Per-section word counts and a rendered browser check |
| M10 | Post-deployment verification probed liveness, so a release with an unreachable database passed | `.github/workflows/cd.yml` | `test_pipeline_contract.py::TestThePostDeploymentProbeReadsReadiness` |
| M11 | The invoker grant was additive, so a pre-existing public invoker survived every apply | `infrastructure/terraform/main.tf`, `scripts/deploy.sh` | `terraform validate` and `plan`; the invoker check executed against captured public, private and empty policies |
| m1 | Generic placeholder values and manual-assistance blocks remained in executable infrastructure and in the workflow | `infrastructure/terraform/main.tf`, `.github/workflows/ci.yml` | `test_pipeline_contract.py::TestNoGateIsAPlaceholder`; zero markers measured in both workflows and the Terraform module |
| m2 | The published reporting and maintainer contacts reached nobody | `SECURITY.md`, `README.md` | `test_documentation_contract.py::TestNoPublishedContactIsAPlaceholder` |
| m3 | The README described a working-directory environment-file default the configuration does not implement, and claimed automation that did not exist | `README.md`, `.github/workflows/ci.yml` | `test_documentation_contract.py::TestTheConfigurationClaimMatches`, `::TestTheAutomationClaimIsTrue` |
| m4 | The credential file the authenticating action writes matched no ignore rule | `.gitignore`, `.dockerignore`, `backend/.dockerignore`, `frontend/.dockerignore`, `.github/workflows/cd.yml` | `test_delivery_surface_contract.py::TestNoCredentialIsPresentWhileAnImageIsBuilt`; `git check-ignore -v` |

Reverse direction — every path this review's remediation changed, and the
findings it was changed for. Twenty-five paths, two of them new:

| Target path | Operation | Findings served |
|---|---|---|
| `backend/app/main.py` | UPDATED | M6 |
| `backend/app/core/config.py` | UPDATED | M6 |
| `backend/app/db/database.py` | UPDATED | M6 |
| `.env.example` | UPDATED | M6 |
| `infrastructure/docker/docker-compose.yml` | UPDATED | M6 |
| `backend/tests/support.py` | UPDATED | M6 |
| `backend/tests/conftest.py` | UPDATED | M6 |
| `backend/tests/security/test_rbac_matrix.py` | UPDATED | M6 |
| `backend/tests/security/test_application_surface.py` | UPDATED | M6 |
| `.gitignore` | UPDATED | m4, and the CI-generated lint report |
| `.dockerignore` | UPDATED | m4 |
| `backend/.dockerignore` | UPDATED | m4 |
| `frontend/.dockerignore` | UPDATED | m4 |
| `infrastructure/terraform/main.tf` | UPDATED | M11, m1 |
| `infrastructure/terraform/variables.tf` | UPDATED | m1 |
| `scripts/deploy.sh` | UPDATED | M1, M2, M11 |
| `.github/workflows/cd.yml` | UPDATED | M3, M4, M10, m4 |
| `.github/workflows/ci.yml` | UPDATED | M4, M5, m1, m3 |
| `backend/tests/security/test_pipeline_contract.py` | **CREATED** | M2, M3, M4, M5, M10, m1, m4 |
| `backend/tests/security/test_documentation_contract.py` | **CREATED** | m2, m3 |
| `README.md` | UPDATED | M6, m2, m3 |
| `SECURITY.md` | UPDATED | m2 |
| `docs/security/DECISION_LOG.md` | UPDATED | M7 |
| `docs/security/TRACEABILITY_MATRIX.md` | UPDATED | M8 |
| `blitzy-deck/executive-summary.html` | UPDATED | M9 |

**Coverage of this set.** All 15 findings appear in the forward table and all 15
are reachable from the reverse table, so both directions are complete for this
review. Every finding maps to at least one path and every path maps to at least
one finding — no row in either table is empty, and no identifier appears that the
review did not raise. The two created paths are test modules, which is why they
serve findings rather than being served by one.

---

## 10. The external-integration seam review — six findings, both directions

A later review examined the seams between this API and the three external systems
it talks to, and raised six findings. They are numbered S1 to S6 here, rather than
reusing the M-and-m form of section 9, precisely because that form is already
taken: two review sets sharing one numbering is the kind of collision this
document exists to prevent.

Two of the six are defects in delivered code, one is a deployment
misconfiguration, and three are this document and its siblings describing a tree
that had moved on. The reasoning for every decision taken in answer is
`docs/security/DECISION_LOG.md` §90.

| # | Finding, as behaviour | Root cause fixed in | Verified by |
|---|---|---|---|
| S1 | The scheduled listing adapter's request shape, parameter names and response fields were never verified against a provider, and no artefact said so plainly — `RESIDUAL_RISK.md` called it "not an open item" | `docs/security/RESIDUAL_RISK.md` O-9; `docs/review/CRITICAL_DECISIONS.md`; `backend/app/services/zillow_service.py` (`DECLARED_PROVIDER_CONTRACT`); `docs/security/DECISION_LOG.md` §92.1 | `test_services.py::TestTheDeclaredListingProviderContract` — the contract is enumerable and immutable, the request is assembled from it, and each departure from it names the element that failed; `test_documentation_citations.py::test_every_open_item_is_registered[O-9]` |
| S2 | Every listing-provider failure became the same empty list a valid empty page returns, and the ingestion pass caught and swallowed it — so a provider outage produced a successful job, a completion record and a stale corpus, and the schedule's retry never engaged | `backend/app/services/zillow_service.py` (`ListingProviderError` and its seven refusal reasons); `backend/app/tasks/listing_updater.py` (rollback then re-raise; the schedule's own catch-log-continue) | `test_services.py` — every failure asserted as a raise naming its reason, and an empty collection asserted a success; `test_tasks.py` — propagation after rollback, whole-pass rollback on a later chunk, schedule continuation, cancellation not absorbed; `test_delivery_pipeline.py::test_the_ingestion_schedule_can_observe_a_failed_pass`; and the process outcome measured directly — non-zero on a refused read, zero on an empty page |
| S3 | The workflow built the browser bundle from `secrets.*` while the manifests were rendered from `vars.*` and the README documented both as variables, so the bundle carried an empty PayPal client identifier; `scripts/deploy.sh` passed no frontend build argument at all | `.github/workflows/cd.yml`; `scripts/deploy.sh`; `docs/security/DECISION_LOG.md` §92.5, §92.6, §92.11; this document's section 3 rows | `test_release_path_contract.py` — both paths pass exactly the `ARG` set `Dockerfile.frontend` declares, both refuse an empty value, and the workflow reads both from the variable context with one shared `vars.PAYPAL_CLIENT_ID` expression; `bash -n`; the script's own argument assembly executed |
| S4 | `DECISION_LOG.md` row 80.6.5 said no ingestion scheduler existed and was never withdrawn, while §82.2 had chosen a CronJob — so `RESIDUAL_RISK.md` O-8 and `CRITICAL_DECISIONS.md` O-8 both sent a reviewer to close a gap that was already closed | `docs/security/DECISION_LOG.md` §92.7, §92.9, §92.12, §92.13 and the marked rows 80.6.5, 82.7, §82.28, §82.29; `docs/security/RESIDUAL_RISK.md` O-7 and O-8; `docs/review/CRITICAL_DECISIONS.md` open-item table and entry 2 checks 4 and 5; `README.md` and `blitzy-deck/executive-summary.html`, which carried the same claim | `test_security_documentation.py::test_every_section_and_row_reference_resolves`; `test_documentation_citations.py` open-item registration and governing-clause cases; `test_operator_documentation.py::test_the_deck_names_every_release_gate`, repinned to the corrected phrase |
| S5 | This document named `frontend/src/services/paypal.ts` as evidence of the hosted redirect, which it is not: it drives the provider's Billing Subscriptions product and never reads the backend's `approval_url` | `docs/security/TRACEABILITY_MATRIX.md` sections 2.7 and 4; `docs/security/DECISION_LOG.md` §92.10 | Read against the authority itself; `test_documentation_citations.py`; the redirect's real evidence is `backend/app/schema/subscription.py`, `backend/app/api/endpoints/subscriptions.py` and `backend/app/services/paypal_service.py`, indexed in sections 2.1, 2.2 and 4 |
| S6 | `CREDENTIAL_ROTATION.md` described secrets synchronised into a Kubernetes Secret and consumed through `envFrom`, which no manifest declares, so an operator would verify a rotation against an object that does not exist | `docs/security/CREDENTIAL_ROTATION.md` runtime-delivery row and its verification steps; `docs/security/DECISION_LOG.md` §92.8 and the marked row §82.4 | `test_delivery_pipeline.py::test_no_credential_reaches_the_api_through_a_cluster_object`, which asserts the one CSI volume is read-only, that the only `secretRef` is the rate-limit store, and that the provider class declares no `secretObjects`; `test_operator_documentation.py` for the runbook's own wording |

Reverse direction — every path this review's remediation changed, and the findings
it was changed for. Nineteen paths, none of them new:

| Target path | Operation | Findings served |
|---|---|---|
| `backend/app/services/zillow_service.py` | UPDATED | S1, S2 |
| `backend/app/tasks/listing_updater.py` | UPDATED | S2 |
| `backend/tests/test_services.py` | UPDATED | S1, S2 |
| `backend/tests/test_tasks.py` | UPDATED | S2 |
| `backend/tests/security/test_application_surface.py` | UPDATED | S2 |
| `backend/tests/security/test_settings_and_redaction.py` | UPDATED | S2 |
| `backend/tests/security/test_delivery_pipeline.py` | UPDATED | S2 |
| `backend/tests/security/test_release_path_contract.py` | UPDATED | S3 |
| `backend/tests/security/test_documentation_citations.py` | UPDATED | S1, S2, S3, S4 |
| `.github/workflows/cd.yml` | UPDATED | S3 |
| `scripts/deploy.sh` | UPDATED | S3 |
| `docs/security/RESIDUAL_RISK.md` | UPDATED | S1, S2, S4 |
| `docs/review/CRITICAL_DECISIONS.md` | UPDATED | S1, S2, S4 |
| `docs/security/DECISION_LOG.md` | UPDATED | S1, S2, S3, S4, S5, S6 |
| `docs/security/TRACEABILITY_MATRIX.md` | UPDATED | S3, S5 |
| `docs/security/CREDENTIAL_ROTATION.md` | UPDATED | S6 |
| `README.md` | UPDATED | S4 |
| `blitzy-deck/executive-summary.html` | UPDATED | S4 |
| `backend/tests/security/test_operator_documentation.py` | UPDATED | S4 |

**Coverage of this set.** All six findings appear in the forward table and all six
are reachable from the reverse table. Every finding maps to at least one path and
every path maps to at least one finding, so both directions are complete with no
empty row and no identifier the review did not raise. `test_documentation_citations.py`
is listed against four findings because it holds the citation and open-item data
every one of them moved.

**One finding was answered differently from its guidance, and that is recorded
rather than absorbed.** S1's guidance was to identify the authoritative listing
provider and implement its exact contract. That is refused on AAP grounds — §0.6.1.2
enumerates the three security changes authorised for that adapter, and §0.9.2
excludes feature additions and directs that findings outside scope be reported for
confirmation — and it is also not available, because no self-serve provider
specification exists to implement. What was delivered instead is the declaration
made enumerable, every departure from it made a loud failure, and the gap
registered as open item O-9 with the operator action that closes it. Row 92.1 of
the decision log carries the alternatives and the reasoning.

---

## 11. The seam review — this round's findings, both directions

Section 9 maps an earlier review of the delivery surface. This section maps a later review
of the seam between this backend and the read-only frontend, and of the documents that
describe the delivered surface. Its findings carry the identifiers that review assigned —
C1 to C4, M1 to M10, and N1 and N2 — and are not the plan's twenty.

Every row names the file the root cause was fixed in and the test or command that verifies
it. Where a finding's subject is a file no test can execute — a workflow, an ignore file, a
Markdown document — the verifying entry is a contract case that reads the file.
`docs/security/DECISION_LOG.md` §89 holds the reasoning for every choice this round made,
including the three positions it withdrew, and none of that reasoning is repeated here.

| # | Finding, as behaviour | Root cause fixed in | Verified by |
|---|---|---|---|
| M1 | The browser accepted a password the request schema refuses, and refused one it accepts, because three length units judge one field — and the deviation was recorded nowhere | `docs/security/DECISION_LOG.md` row 93.1 | The row's measured divergence cases; `test_login_lockout_and_rate_limit.py::test_the_byte_ceiling_counts_bytes_and_not_characters`, `::test_a_registration_password_beyond_the_byte_ceiling_is_refused`, `::test_a_login_password_beyond_the_byte_ceiling_is_refused`, `::test_a_password_at_the_byte_ceiling_is_accepted`, `::test_a_password_failing_the_policy_floor_is_refused` |
| M2 | The frontend image build read two public values from the secret namespace while the same workflow read one of them from the variable namespace, so at most one provisioning could ever be populated | `.github/workflows/cd.yml` | The workflow parse; `bash -n` over every `run` body; the new preflight refusal executed over all four populated-and-blank combinations |
| M3 | The documented generic redirect values default to a development port and silently replaced the Compose defaults, which target the port Compose publishes | `infrastructure/docker/docker-compose.yml`, `.env.example` | Compose interpolation evaluated before and after the change; `test_deployment_contract.py`'s alias table, which asserts each alias is both consumed and documented |
| M4 | The deployment section named a variable as a secret, named a runner variable that does not exist, listed script inputs that are retired, and described a rollout mechanism the script does not use | `README.md` | `test_security_documentation.py`, `test_operator_documentation.py`, `test_documentation_citations.py` |
| M5 | The policy told an operator to discount a failing frontend job in the same document that says no job is tolerated, and asserted that no Kubernetes manifests exist | `SECURITY.md` | `test_security_documentation.py`, `test_documentation_contract.py` |
| M6 | The residual-risk register's O-7 asserted that no cluster workload objects are declared here, which the committed inventory disproves, and O-8 said the same of the ingestion trigger | `docs/security/RESIDUAL_RISK.md` | `test_documentation_citations.py`'s open-item inventory, now O-1 to O-9; the twelve manifests and the render groups themselves |
| M7 | The reviewer-facing appendix repeated the same withdrawn claims about the cluster inventory and the ingestion trigger | `docs/review/CRITICAL_DECISIONS.md` | `test_documentation_citations.py`; `test_operator_documentation.py`'s assertion that Rule 3's artifact still carries exactly five decisions |
| M8 | The presentation claimed every finding was covered by a test while its own metric grid reported fifteen and five, placed the cluster objects and the secret mount outside this repository, and told a reader the frontend job was expected to fail | `blitzy-deck/executive-summary.html` | `test_operator_documentation.py::test_the_assurance_split_is_reported_wherever_the_total_is`, `::test_the_deck_title_hands_deployment_and_rotation_to_an_operator`, `::test_the_deck_counts_findings_as_remediated_and_tested`, `::test_the_deck_names_every_release_gate`; `test_deck_contract.py` and `test_presentation_contract.py` for the Rule 2 budgets; a rendered browser pass over all eighteen sections |
| M9 | Four different delivered-path totals stood in this document at once, and its plan-entry figure disagreed with the plan's own | `docs/security/TRACEABILITY_MATRIX.md` | `test_operator_documentation.py`, which recomputes the delivered set from the tree and both published figures from this document |
| M10 | An accepted deviation from the obvious reading of the password policy carried no decision row, so it read as an oversight rather than a choice | `docs/security/DECISION_LOG.md` §89 | The section itself, its eleven five-column rows and its three withdrawals; `test_documentation_contract.py` for its checkable claims |
| N1 | `.gitignore` carried the same credential-file block three times, so three copies of one rule had to be reconciled before any could be trusted | `.gitignore` | `git check-ignore -v` at the root and at depth; `.github/scripts/check_secret_policy.sh`; `test_delivery_surface_contract.py::test_the_credential_name_is_ignored_everywhere` |
| N2 | The same block was repeated in `.dockerignore`, and in the two build-context ignore files the review did not cite | `.dockerignore`, `backend/.dockerignore`, `frontend/.dockerignore` | `git check-ignore -v`; `test_delivery_surface_contract.py::test_the_credential_name_is_ignored_everywhere`, which requires the anchored and recursive pair in each of the four ignore files |

**Five of this review's findings are repairs inside read-only frontend source, and no file
here changes for them.** They are recorded rather than remediated, which the plan's §0.9.2
requires and §0.1.2 reinforces: the opposite repair, moving this backend to meet the client,
would have to change the login response shape and route paths that clause freezes.

| # | Finding, as behaviour | Where it is recorded | Why no file here changes |
|---|---|---|---|
| C1 | The authentication client imports a symbol its dependency declares without exporting, posts to a path this backend does not serve, and reads response members it does not return | `docs/security/DECISION_LOG.md` rows 29.7 and 73.7, and row 80.6.3; `docs/security/RESIDUAL_RISK.md` O-5 | The repair is inside `frontend/src/services/auth.ts`, and §0.9.2 places `frontend/src/**` out of scope |
| C2 | An authenticated request is sent with no `Authorization` header and no interceptor to add one, beside a profile route that does not exist | `docs/security/DECISION_LOG.md` rows 29.8 and 73.8, and row 80.6.3 | The repair is inside `frontend/src/services/api.ts`, out of scope by the same clause |
| C3 | The payment client drives the provider's subscription product while this backend implements orders, and imports a dependency the manifest declares nowhere | `docs/security/DECISION_LOG.md` rows 29.9 and 73.9; `docs/security/RESIDUAL_RISK.md` O-6, and O-9 for the undeclared dependency | The repair is inside `frontend/src/services/paypal.ts` and `frontend/package.json`, both out of scope by §0.9.2 |
| C4 | The subscription interface is declared without `export` and four of its five members do not match the response | `docs/security/DECISION_LOG.md` rows 29.10 and 73.10 | The repair is inside `frontend/src/schema/subscription.ts`, out of scope by §0.9.2 |
| M1 | The implementation half of the length-unit divergence: making the browser validator count what the request schema counts | `docs/security/DECISION_LOG.md` row 93.1, which records the measurement and both rejected repairs | The repair is inside `frontend/src/utils/validators.ts`, which §0.6.1.7 lists as a read-only reference; the documentation half is the obligation this change set owns, and the M1 row in the forward table above discharges it |

Reverse direction — every path this round's remediation changed, and the findings it was
changed for. Nineteen paths, none of them new:

| Target path | Operation | Findings served |
|---|---|---|
| `.gitignore` | UPDATED | N1 |
| `.dockerignore` | UPDATED | N2 |
| `backend/.dockerignore` | UPDATED | N2, at the same root cause |
| `frontend/.dockerignore` | UPDATED | N2, at the same root cause |
| `.github/workflows/cd.yml` | UPDATED | M2 |
| `infrastructure/docker/docker-compose.yml` | UPDATED | M3 |
| `.env.example` | UPDATED | M3 |
| `README.md` | UPDATED | M4 |
| `SECURITY.md` | UPDATED | M5 |
| `docs/security/RESIDUAL_RISK.md` | UPDATED | M6 |
| `docs/review/CRITICAL_DECISIONS.md` | UPDATED | M7 |
| `docs/security/TRACEABILITY_MATRIX.md` | UPDATED | M9, and this section for M1 and M10 |
| `docs/security/DECISION_LOG.md` | UPDATED | M10, M1 |
| `backend/tests/security/test_deployment_contract.py` | UPDATED | M3 — the two aliases added to its alias table |
| `backend/tests/security/test_documentation_citations.py` | UPDATED | M6, M7 — the open-item inventory extended to O-9 |
| `backend/tests/security/test_operator_documentation.py` | UPDATED | M9 — the published identities it recomputes |
| `backend/tests/security/test_security_documentation.py` | UPDATED | M4, M5, M9 — the delivered-path constants it derives |
| `backend/tests/security/test_deck_contract.py` | UPDATED | M8 — the diagram case whose premise the delivered manifests had overtaken |
| `blitzy-deck/executive-summary.html` | UPDATED | M8, and M9 for the two figures it quotes from this document |

**Coverage of this set.** All 16 findings appear above and all 16 are reachable from one of
the two reverse directions: the 11 remediated here from the reverse table, and the 5
frontend-source findings from the table of records that hold them. Every finding maps to at
least one path or record and every path maps to at least one finding — no cell is empty, and
no identifier appears that this review did not raise. No path is new, which is why the
delivered totals in the introduction and section 2.10 are unchanged by this round: it
corrected documents and configuration that were already in the delivered set.

---


### What this document deliberately does not contain

Each omission is a boundary with a sibling document, not a gap in coverage.

- **No rationale.** Rule 1 makes `docs/security/DECISION_LOG.md` the single source of truth
  for *why*, and none of the tables above carries a "why" column.
- **No residual-advisory evidence.** The accepted advisories — 7 in the runtime register
  and 7 more in the development register, 14 in total and disjoint — the measured version
  ceilings under the runtime pin, and the reachability measurement behind each compensating
  control all belong to `docs/security/RESIDUAL_RISK.md`. Where a figure in this file names
  7, it names the runtime register alone, which is the set the deployed image installs.
- **No rotation steps.** The ordered runbook for the exposed credentials belongs to
  `docs/security/CREDENTIAL_ROTATION.md`. That sequence is the reason C-4's row in section 1
  names a manual verification: removing a credential from the tree does not remove it from
  history, so the finding is not closed by any file change alone.
- **No secret, credential, key, token or connection string,** not even illustratively. Every
  line that carries one — `infrastructure/docker/docker-compose.yml:30` and `:31`, and
  `scripts/setup_dev_environment.sh:54`, `:55` and `:69` — is cited by path and line only.
  The one literal that does appear, `your_secret_key_here`, is not a secret: it is the
  placeholder on the rejected-value denylist that C-1 turns into a startup failure.
- **No repository-wide file count.** This document indexes the paths this remediation
  created, modified or withdrew — **156** rows, being the **130** delivered paths, the
  **9** read-only references it confirms unmodified and the **17** paths the manifest
  consolidation retired. It does not count the repository's other files, which this work
  never touched. The introduction and section 2.10 publish that measurement; every earlier
  total, including the `69 + 24 = 93` this sentence once carried, is listed as a superseded
  snapshot in section 2.10 rather than left standing beside the current one.
  `docs/security/DECISION_LOG.md` §23.1 remains the authority for the
  planned-versus-actual reconciliation, and §23.2 and §35.3 for why each unplanned
  path exists.
  **An earlier revision of this file published no delivered-path total and deferred the
  whole question to the decision log.** That left real delivered paths —
  `backend/.dockerignore`, `setup.cfg` and several test modules among them — reachable
  from neither index here while this section claimed complete coverage. Section 2.9 closes
  that gap and section 2.10 makes the closure countable.
- **No per-round scope in sections 1 to 8.** The per-round traceability sections of
  `docs/security/DECISION_LOG.md` are additive records of individual review rounds. Sections
  1 to 8 here are the whole-project mapping Rule 1 requires, spanning all 20 findings rather
  than any single round's subset. Sections 9 and 10 are the two exceptions and say so in
  their own titles: each maps a later review whose findings are not the plan's 20, and each
  is kept apart from the whole-project sections so that no identifier from either is counted
  among them.

### Two boundaries recorded for accuracy

**The Python 3.9 runtime pin is deliberately unchanged at every site.** Sections 1 and 2
cite `infrastructure/terraform/main.tf`, `scripts/deploy.sh`,
`.github/workflows/ci.yml` and `infrastructure/docker/Dockerfile.backend` for
neighbouring findings. In each case the pin itself is preserved — `runtime = "python39"`,
`--runtime python39`, `python-version: '3.9'` and `FROM python:3.9-slim` respectively —
and nothing in this matrix should be read as mapping a runtime change. These are named by
construct rather than by line because they are claims about the tree as it stands, and
each is asserted by `test_the_runtime_pin_is_still_carried_at_every_site`. Where a
reviewer needs the exact line to open, `docs/review/CRITICAL_DECISIONS.md` carries it,
and the numbers there are themselves gated by
`test_every_documented_pin_site_line_is_correct`. Where an advisory's only fix requires a newer
interpreter, the outcome is documented residual risk in `docs/security/RESIDUAL_RISK.md`,
never a runtime bump.

**The findings discovered outside the stated scope are flagged and awaiting confirmation.**
None is fixed by this work, none appears in this matrix, and none is counted among the 20.
They are enumerated as an itemised inventory at `docs/security/DECISION_LOG.md` §35.1, which
expands the bare count published at row 34.6.3 and is where they should be read; row 91.8.1
confirms that all ten are still unchanged in the delivered tree, and §91.1 records the two
that a later round changed and this round reverted. One of them is no longer true of the tree
rather than fixed: `frontend/package-lock.json` is now tracked, so the reported absence of a
frontend lock file is closed by a change of state, and §35.1 records it that way rather than
as a remediation.

The one compliance-relevant property this matrix records is factual and unchanged: the
payment flow remains a hosted redirect, so no card number enters or is stored by this
service. Every payment row above maps order identifiers, plan identifiers and webhook
notifications; none pulls cardholder data inward. No conformance to any compliance
framework is claimed.

---
