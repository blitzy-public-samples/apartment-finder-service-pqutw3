# Traceability Matrix

This document is the bidirectional traceability matrix that Rule 1 (Explainability)
requires for a migration or a refactor. This remediation is both: it introduces two
Alembic revisions where the repository previously had no migration framework, and it
replaces three dependencies — `python-jose` with PyJWT, `passlib` with direct `bcrypt`
calls, and `paypalrestsdk` with REST calls over `httpx`. The Rule's traceability clause
is therefore engaged on two independent grounds, and this file is not discretionary.

The matrix is bidirectional at 100% coverage with no gaps. Its defining property is that
completeness can be confirmed by counting rather than by trusting an assertion, so every
total below is stated explicitly and every total is addable.

## Totals

| Quantity | Figure |
|---|---|
| Findings mapped | **20** — C-1 to C-4, H-1 to H-7, M-1 to M-4, INFRA-1 to INFRA-5 |
| Entries in the plan's transformation mapping | **68** |
| — of those, CREATE | **30** |
| — of those, UPDATE | **29** |
| — of those, DELETE | **0** |
| — of those, REFERENCE | **9** |
| Dependency advisories | **19 across 7 packages** before, **7 across 3** after |
| Static-analysis findings at Medium or above | **1** before, **0** after |
| Role-matrix assertions | **45** — 9 routes across 5 principals |
| Accounts holding the administrative role after migration | exactly **1** |

`30 + 29 + 0 + 9 = 68`.

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
it; Axis 2 runs from each replaced construct to the construct that replaced it; and the
reverse index in section 4 runs backward from each target file to the finding it serves
and the test that covers it. Every finding and every target file is therefore reachable
from both directions, which is what the Rule's word "bidirectional" requires and what a
one-way listing would not satisfy.

## Two conventions this file follows

**Line numbers locate the baseline tree.** Every line number cited below resolves against
revision `a26f7fb`, the last revision before this remediation began. Most of the files
named here have since been rewritten, so a baseline line number will not resolve against
the current tree — `@asyncio.coroutine` at `backend/app/tasks/listing_updater.py:10` is
one of several. Baseline numbers are kept because they are what the findings and the plan
cite. This is the same convention `docs/security/DECISION_LOG.md` adopts, and every
location in section 3 was read back from that revision rather than copied from a summary.

**The figure 68 counts plan entries, not changed files.** It is 59 planned changes — the
30 CREATE and 29 UPDATE entries — plus the 9 read-only REFERENCE paths, which are read
and never modified. The two quantities are not interchangeable, and this matrix does not
present 68 as a count of changed files. `docs/security/DECISION_LOG.md` §23.1 is the
authority for the planned-versus-actual reconciliation, including the paths delivered
beyond the plan that its §23.2 enumerates; that section should be read before this figure
is quoted anywhere.

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
| **INFRA-2** | CI and CD carry no `permissions` block, no dependency or SAST gate, and authenticate with a long-lived service-account key | High | `.github/workflows/ci.yml` declares no `permissions` and at `:44` invokes a linter it never installs; `.github/workflows/cd.yml:26` supplies a long-lived key | `.github/workflows/ci.yml`, `.github/workflows/cd.yml` | The CI gates themselves: `pip-audit -r backend/requirements.txt`, `bandit -r backend/app -ll`, the security suite, and the two compensating-control guards. The interpreter pin at `ci.yml:19` is deliberately left unchanged |
| **INFRA-3** | The backend image runs as root and copies the whole tree with no `.dockerignore`, so any local environment file or secrets directory is baked into the image | Medium | `infrastructure/docker/Dockerfile.backend:14` copies the tree unfiltered and the file declares no `USER`; `:8` copies a manifest that did not exist, so the build failed before any security consideration | `infrastructure/docker/Dockerfile.backend`, `.dockerignore` | The container build verification, plus `backend/tests/security/test_deployment_contract.py`. The base image tag at `:2` is deliberately left unchanged |
| **INFRA-4** | The deployment script has no failure handling, authenticates from an on-disk key file, and deploys the Cloud Function with `--allow-unauthenticated` | High | `scripts/deploy.sh:1` sets no shell failure options, `:5` activates a service account from a key file, and `:24` passes the unauthenticated-invocation flag | `scripts/deploy.sh` | Review verification against the script; no automated coverage targets this file, which is stated rather than implied. The runtime pin at `:24` is deliberately left unchanged |
| **INFRA-5** | No Python dependency manifest exists anywhere in the repository, so the running dependency set is unversioned and uninventoried | High | Absence under `backend/`: no `requirements.txt`, `Pipfile`, `pyproject.toml` or lock file, while `infrastructure/docker/Dockerfile.backend:8` copies one | `backend/requirements.txt`, `backend/requirements-dev.txt` | `pip-audit -r backend/requirements.txt` and `pip-audit -r backend/requirements-dev.txt`, invoked against the manifest rather than the environment |

**Distinct findings in this table: 20.** No identifier is duplicated and none is invented.

---

## 2. Axis 1 continued — the plan's 68 transformation entries

The same forward direction, enumerated by target path so that every entry in the plan's
transformation mapping is accounted for. Groups follow the plan's own grouping. Each row
names the path, the transformation mode, and the finding it serves. Rows whose authority
is a Rule rather than a finding name the Rule, so that no cell is left empty.

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
| `backend/app/api/router.py` | REFERENCE — listed, not counted in the 9; see section 2.8 | H-4, as negative evidence: the new webhook route mounts under the existing `/subscriptions` prefix, so this file needs no edit, which is what demonstrates the four-prefix constraint is honoured |

Counted subtotal: 3 CREATE + 7 UPDATE = **10**.

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
| `backend/tests/conftest.py` | CREATE | Fixtures for C-1 to INFRA-5; its absence was a direct cause of the baseline collection failure |
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
`security/`. Modules delivered beyond this enumerated set are recorded in
`docs/security/DECISION_LOG.md` §23.2 and are additive: several appear in the verifying-test
column of section 1 because they hold the closest coverage of a finding, and each is
attributed there by path.

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

When this file was written, `docs/security/RESIDUAL_RISK.md`,
`docs/security/CREDENTIAL_ROTATION.md`, `docs/review/CRITICAL_DECISIONS.md`,
`blitzy-deck/executive-summary.html` and `SECURITY.md` were not yet present in this
working tree; each is owned by a sibling checkpoint. `docs/security/DECISION_LOG.md`
records that position at its rows 26.19, 29.11, 30.15, 32.12 and 33.11. Their rows appear
above because the plan's mapping contains them, and the mode column states the plan's
intent rather than a delivery claim.

### 2.7 Read-only references

Nine paths read to constrain the design and never modified.

| Target path | Mode | Serves |
|---|---|---|
| `frontend/src/services/auth.ts` | REFERENCE | H-7 — establishes the token-storage contract, which forecloses moving the token into a cookie |
| `frontend/src/services/paypal.ts` | REFERENCE | H-2, H-3 — confirms the hosted redirect and that no client sends an amount |
| `frontend/src/schema/subscription.ts` | REFERENCE | H-2 — the response shape the backend must keep satisfying; it carries no amount field |
| `frontend/src/utils/validators.ts` | REFERENCE | C-1 — the documented password policy the new server-side guard realizes |
| `frontend/package.json` | REFERENCE | INFRA-2 — confirms the lock-file assumption the pipeline makes |
| `infrastructure/docker/Dockerfile.frontend` | REFERENCE | INFRA-3 — confirms the same lock-file assumption; no backend security bearing |
| `documentation/Technical Specifications.md` | REFERENCE | H-1 — design-intent authority for the four roles and the absent secret management |
| `documentation/Software Requirements Specifications (SRS).md` | REFERENCE | M-1 — design-intent authority for the lockout parameters and the password policy |
| `documentation/Software Project Proposal.md` | REFERENCE | INFRA-2 — design-intent authority for the coverage targets |

Counted subtotal: 9 REFERENCE = **9**.

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
`30 + 29 = 59` planned changed paths that `docs/security/DECISION_LOG.md` §23.1
reconciles against the tree.

Two properties of this count are worth stating so a reviewer can reproduce it rather than
re-derive it.

**`backend/app/api/router.py` is listed but not counted among the 9.** It is the one
reference-mode row the plan carries inside its application-core group rather than in its
read-only-references group, so the nine REFERENCE entries of section 2.7 are the whole of
the counted reference set. Rendering it in section 2.1 keeps its evidentiary role visible
— a file needing no edit is what proves the four router prefixes were preserved — while
leaving the 68 arithmetic intact. Counting it twice would give 69 and contradict the
totals every other document in this change set quotes.

**The DELETE column is 0, and that is a finding about the repository rather than an
omission here.** No file in this repository existed solely to introduce a vulnerability,
so the mode had no legitimate target; `docs/security/DECISION_LOG.md` §34.7.1 records the
position, including why two unplanned byproduct files removed during the work leave this
column at 0.

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
| `Base.metadata.create_all(bind=engine)` | `backend/app/main.py:18`, invoked at `:33` | The two Alembic revisions, which own the schema instead | H-1 |

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

This section is what makes the matrix bidirectional. Sections 1 to 3 run forward from a
finding to the files and constructs that answer it; this table runs backward, so a reader
holding a file in hand can establish which finding it exists to remediate and which test
proves it did. Every target path from sections 2.1 to 2.7 appears exactly once, in the same
order. Where a path carries no finding, its governing authority is recorded instead, so no
cell is empty.

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
| `backend/requirements-dev.txt` | INFRA-5 | `pip-audit -r backend/requirements-dev.txt` |
| `backend/alembic.ini` | H-1 | `alembic upgrade head`, then `alembic downgrade -1` twice; `test_migration_gate.py` |
| `backend/migrations/env.py` | H-1 | `test_migrations.py` |
| `backend/migrations/script.py.mako` | H-1 | `test_revision_contracts.py` |
| `backend/migrations/versions/0001_add_rbac_and_subscription_columns.py` | H-1, H-3, H-4 | `test_migrations.py`, `test_migration_revisions.py` |
| `backend/migrations/versions/0002_seed_single_admin.py` | H-1 | `test_admin_seed_migration.py`, asserting exactly 1 administrator as a post-condition |
| `backend/tests/conftest.py` | Fixtures for every finding; its absence caused the baseline collection failure | `pytest backend/tests -q`, which collects only once these fixtures exist |
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
| `infrastructure/terraform/main.tf` | C-4, INFRA-1 | `terraform validate` |
| `infrastructure/terraform/variables.tf` | INFRA-1 | `terraform validate` |
| `infrastructure/terraform/outputs.tf` | INFRA-1 | `terraform validate`, which fails at baseline on this file's dangling references |
| `.github/workflows/ci.yml` | INFRA-2 | The gates it runs: `pip-audit`, `bandit -r backend/app -ll`, the security suite, and the two compensating-control guards |
| `.github/workflows/cd.yml` | INFRA-2, C-4 | Review verification of the federated-identity exchange, the migration step and the health probe |
| `scripts/deploy.sh` | INFRA-4 | Review verification; no automated coverage targets this file |
| `scripts/setup_dev_environment.sh` | C-1, C-4 | `test_setup_script.py`, `test_setup_script_bootstrap.py` |
| `docs/security/DECISION_LOG.md` | Rule 1 (Explainability) — decision-log clause | Review against Rule 1: every non-trivial decision carries alternatives, reasoning and risk |
| `docs/security/TRACEABILITY_MATRIX.md` | Rule 1 (Explainability) — bidirectional-matrix clause | The count checks in section 5 of this file |
| `docs/security/RESIDUAL_RISK.md` | The accepted-residual-risk instruction | `pip-audit -r backend/requirements.txt` reporting exactly the 7 documented advisories, plus the two compensating-control guards |
| `docs/security/CREDENTIAL_ROTATION.md` | C-4 | Manual confirmation that the documented order was followed |
| `docs/review/CRITICAL_DECISIONS.md` | Rule 3 (Critical Decision Review Document) | Review against Rule 3: five entries ordered highest risk first, each with alternatives, risk level and an assigned reviewer with named checks |
| `blitzy-deck/executive-summary.html` | Rule 2 (Executive Presentation) | Review against Rule 2: the file opens in a browser, renders its diagrams and icons, and every section carries a non-text visual |
| `SECURITY.md` | Disclosure policy and supported-version statement | Review for presence and accuracy of the disclosure contact and supported versions |
| `README.md` | C-1, C-4, and notice of the one intentional breaking change | Review that the breaking change is stated and the verification commands resolve |
| `frontend/src/services/auth.ts` | H-7 — read-only reference establishing the token-storage contract | Confirmed unmodified; absent from the changed set |
| `frontend/src/services/paypal.ts` | H-2, H-3 — read-only reference confirming the hosted redirect | Confirmed unmodified; absent from the changed set |
| `frontend/src/schema/subscription.ts` | H-2 — read-only reference for the response shape | Confirmed unmodified; absent from the changed set |
| `frontend/src/utils/validators.ts` | C-1 — read-only reference for the documented password policy | Confirmed unmodified; absent from the changed set |
| `frontend/package.json` | INFRA-2 — read-only reference for the lock-file assumption | Confirmed unmodified; absent from the changed set |
| `infrastructure/docker/Dockerfile.frontend` | INFRA-3 — read-only reference for the same assumption | Confirmed unmodified; absent from the changed set |
| `documentation/Technical Specifications.md` | H-1 — read-only design-intent authority for the four roles | Confirmed unmodified; absent from the changed set |
| `documentation/Software Requirements Specifications (SRS).md` | M-1 — read-only design-intent authority for the lockout parameters | Confirmed unmodified; absent from the changed set |
| `documentation/Software Project Proposal.md` | INFRA-2 — read-only design-intent authority for the coverage targets | Confirmed unmodified; absent from the changed set |

Test modules are named by file above rather than by full path, since every one resides in
`backend/tests/` or `backend/tests/security/` as section 2.4 and
`docs/security/DECISION_LOG.md` §23.2 record. Modules appearing here but not in section 2.4
are delivered beyond the plan's enumerated set and are attributed to §23.2.

---

## 5. Completeness statement

Rule 1 requires 100% coverage with no gaps. That is a countable claim, so the counts that
substantiate it are given here rather than asserted.

**Findings, both directions.** Section 1 maps **20** distinct findings forward to their
target files and verifying tests: C-1, C-2, C-3, C-4, H-1, H-2, H-3, H-4, H-5, H-6, H-7,
M-1, M-2, M-3, M-4, INFRA-1, INFRA-2, INFRA-3, INFRA-4 and INFRA-5. All **20** appear again
in the reverse index of section 4, reached from the target-file side. No identifier is
duplicated, and none is invented: the set is exactly the plan's finding register.

**Entries, both directions.** Sections 2.1 to 2.7 enumerate **68** transformation entries
forward by target path. The reverse index of section 4 contains the same **68** paths plus
`backend/app/api/router.py`, which section 2.1 lists as a reference-mode row that is not
counted among the 9. The mode subtotals reconcile as
**30 CREATE + 29 UPDATE + 0 DELETE + 9 REFERENCE = 68**, and the group subtotals of
section 2.8 add to the same figure: `10 + 10 + 7 + 12 + 12 + 8 + 9 = 68`. The CREATE and
UPDATE columns alone give the **59** planned changed paths that
`docs/security/DECISION_LOG.md` §23.1 reconciles against the tree.

**Constructs.** Section 3 maps every replaced construct to its replacement across the three
dependency refactors and the two migration revisions that supersede schema creation at
import time, with each baseline location read back from revision `a26f7fb`.

**No empty cells.** Every row in every table above carries a value in every column. Where a
path serves no finding — the four `docs/security/` artefacts, `docs/review/CRITICAL_DECISIONS.md`,
`blitzy-deck/executive-summary.html` and `SECURITY.md` — its governing Rule or instruction
is recorded in place of a finding identifier, and a review activity is recorded in place of
an automated test.

### What this document deliberately does not contain

Each omission is a boundary with a sibling document, not a gap in coverage.

- **No rationale.** Rule 1 makes `docs/security/DECISION_LOG.md` the single source of truth
  for *why*, and none of the tables above carries a "why" column.
- **No residual-advisory evidence.** The 7 accepted advisories, the measured version
  ceilings under the runtime pin and the reachability measurement behind each compensating
  control belong to `docs/security/RESIDUAL_RISK.md`.
- **No rotation steps.** The ordered runbook for the exposed credentials belongs to
  `docs/security/CREDENTIAL_ROTATION.md`. That sequence is the reason C-4's row in section 1
  names a manual verification: removing a credential from the tree does not remove it from
  history, so the finding is not closed by any file change alone.
- **No secret, credential, key, token or connection string,** not even illustratively. Every
  line that carries one — `infrastructure/docker/docker-compose.yml:30` and `:31`, and
  `scripts/setup_dev_environment.sh:54`, `:55` and `:69` — is cited by path and line only.
  The one literal that does appear, `your_secret_key_here`, is not a secret: it is the
  placeholder on the rejected-value denylist that C-1 turns into a startup failure.
- **No delivered-path total, and no repository-wide file count.** The only entry counts this
  document publishes are the plan's 68 and its 30 / 29 / 0 / 9 breakdown.
  `docs/security/DECISION_LOG.md` §23.1 is the authority for how many paths were actually
  changed, and §23.2 for those delivered beyond the plan.
- **No per-round scope.** The per-round traceability sections of
  `docs/security/DECISION_LOG.md` are additive records of individual review rounds. This
  matrix is the whole-project one Rule 1 requires, spanning all 20 findings rather than any
  single round's subset.

### Two boundaries recorded for accuracy

**The Python 3.9 runtime pin is deliberately unchanged at every site.** Sections 1 and 2
cite `infrastructure/terraform/main.tf:99`, `scripts/deploy.sh:24`,
`.github/workflows/ci.yml:19` and `infrastructure/docker/Dockerfile.backend:2` for
neighbouring findings. In each case the pin itself is preserved, and nothing in this matrix
should be read as mapping a runtime change. Where an advisory's only fix requires a newer
interpreter, the outcome is documented residual risk in `docs/security/RESIDUAL_RISK.md`,
never a runtime bump.

**The ten findings discovered outside the stated scope are flagged and awaiting
confirmation.** None is fixed or resolved by this work, none appears in this matrix, and
none is counted among the 20. They are enumerated at `docs/security/DECISION_LOG.md` row
34.6.3, which is where they should be read.

The one compliance-relevant property this matrix records is factual and unchanged: the
payment flow remains a hosted redirect, so no card number enters or is stored by this
service. Every payment row above maps order identifiers, plan identifiers and webhook
notifications; none pulls cardholder data inward. No conformance to any compliance
framework is claimed.
