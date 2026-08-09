# Apartment Finder Service

An apartment-listing discovery service. A background ingestion task queries a Zillow
listing endpoint and persists the results, and an end-user API exposes authentication,
the listing corpus, user-owned saved filters, and premium subscriptions paid through
PayPal. The backend is Python 3.9 with FastAPI, SQLAlchemy and PostgreSQL; a React
frontend consumes the API.

> **Breaking change in this release.** `POST /listings/` now requires the `admin` role.
> See [Breaking change](#breaking-change-post-listings-now-requires-the-admin-role)
> for the consumer action.

## Features

- Registration and login issuing a signed access token.
- Role-based access control across the API, with an ordered `guest` / `registered` /
  `premium` / `admin` model that denies by default.
- A publicly readable listing corpus with bounded pagination, and administrator-only
  listing writes.
- Saved search filters scoped to the account that owns them.
- Premium subscriptions priced from a server-owned plan catalog, using PayPal's hosted
  redirect, with a signature-verified and replay-protected webhook listener.
- Background ingestion of listings from a Zillow endpoint.

## System Requirements

| Requirement | Version | Notes |
| --- | --- | --- |
| CPython | **3.9** | A hard pin. See the note below. |
| PostgreSQL | 13 | The version the container and infrastructure definitions target. |
| Docker | Any current release | Optional; only needed for the container workflow. |
| Node.js | 14, as pinned by the frontend image and CI job | Only for the `frontend/` workspace. Not needed to run the API. This major version has reached end of life; that is a reported finding awaiting confirmation, not a resolved one — see [Security Documentation](#security-documentation). |

**The Python 3.9 pin is a hard constraint and is load-bearing in five places:**
`infrastructure/docker/Dockerfile.backend`, `.github/workflows/ci.yml`, the Cloud
Function runtime in `infrastructure/terraform/main.tf`, `scripts/deploy.sh`, and a
decorator in `backend/app/tasks/listing_updater.py` that a newer interpreter would
break. Where a dependency's only available fix requires a newer interpreter, the
advisory is recorded as accepted residual risk instead — see
[`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md).

## Security and Setup

### Environment configuration

All configuration is supplied through environment variables read by
`backend/app/core/config.py`, a Pydantic v1 `BaseSettings` class configured with
`env_file = ".env"`. **[`.env.example`](.env.example) is the authoritative catalog of
every variable** — its comments carry the accepted values, defaults and validation rules
for each one, so consult it rather than any list reproduced elsewhere.

Bootstrap:

```bash
cp .env.example .env
```

Then generate a real signing key and put it in `.env` as `SECRET_KEY`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
# or
openssl rand -base64 48
```

**Configuration is validated when the application starts, and a rejected value stops
startup rather than being defaulted or downgraded.** This is intended behaviour: a
refusal here is a guard reporting a misconfiguration, not a defect. Startup fails when

- `SECRET_KEY` is shorter than the floor set by the strongest algorithm in
  `JWT_ALGORITHMS` (32 bytes for HS256, 48 for HS384, 64 for HS512), or matches a
  placeholder or well-known value on the denylist — including the value this repository's
  template ships, which is refused in every environment;
- `JWT_ALGORITHMS` names anything outside the `HS256` / `HS384` / `HS512` allowlist, and
  `none` is rejected in any letter case;
- `ENVIRONMENT=production` is paired with sandbox payment credentials.

`.env` is git-ignored. **`.env.example` is the only committed environment file, and no
secret value belongs in it** — every secret-bearing entry there is a non-functional
placeholder.

Two operational notes:

- `PAYPAL_WEBHOOK_ID` must be provisioned in the PayPal developer console before the
  webhook listener can verify anything; it is one of the inputs to signature verification.
- Credentials previously committed to this repository must be treated as compromised.
  Rotation is documented separately and is sequenced last, after every other change has
  been verified — see
  [`docs/security/CREDENTIAL_ROTATION.md`](docs/security/CREDENTIAL_ROTATION.md).

### Local setup and run

```bash
python3.9 -m venv .venv && . .venv/bin/activate
python -m pip install --upgrade pip
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
```

Apply the schema with Alembic:

```bash
cd backend && alembic upgrade head
```

**The schema is now owned by migrations.** The `Base.metadata.create_all` call that ran
at application import time has been removed. **Migrations must run before the new code
serves traffic**, because the authorization dependency reads a column the migration adds.
Every added column carries a server default, so the schema change is reversible from the
code.

Run the server:

```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Run it from the repository root: the packages resolve as implicit namespace packages, and
the module path is `backend.app.main:app`. Liveness is at `GET /health`; readiness, which
answers 503 while the database is unreachable, is at `GET /health/ready`.

`scripts/setup_dev_environment.sh` performs the whole sequence in one step — virtual
environment, both dependency manifests, the environment file with a generated signing key,
the database role and database, and the schema — and stops at the first failing step.

### Running with Docker

```bash
docker build -f infrastructure/docker/Dockerfile.backend \
  -t apartment-finder-backend:verify backend/
```

The stack is selected by profile. Copy `.env.example` to `infrastructure/docker/.env`,
fill it in, then:

```bash
docker compose -f infrastructure/docker/docker-compose.yml --profile local up -d
```

The `local` profile runs PostgreSQL 13 as the `db` service; the `gcp` profile answers to
`db` with a Cloud SQL proxy instead. Under either profile a one-shot `migrate` service
applies the Alembic revisions first, and the backend starts only once that service has
exited successfully. No value in the compose file is a credential: every mandatory
setting is a required substitution, so the stack stops and names the variable when one is
absent.

The backend image **runs as a non-root user**, and the **published port is aligned to
8000**, which is the port the image exposes and the port the health check probes.

### Verification

These are the measurable gates for this work. Run them from the repository root with the
virtual environment active.

| Command | Expected result |
| --- | --- |
| `python -c "import backend.app.main"` | Exit code 0 — the application imports. |
| `python -m pytest backend/tests -q` | Tests collected, all passing. |
| `python -m pytest backend/tests/security -q` | All passing, including the **45-assertion role matrix** — nine role-governed routes by five principals, anonymous included. |
| `pip-audit -r backend/requirements.txt` | **Only** the seven documented residual advisories. |
| `pip-audit -r backend/requirements-dev.txt` | No advisory outside the set documented in that manifest's header. |
| `bandit -r backend/app -ll` | Exit code 0 — no Medium or High findings. |
| `flake8 backend` | Clean. |
| `cd infrastructure/terraform && terraform init -backend=false && terraform validate` | Passes. |
| `cd backend && alembic upgrade head`, then `alembic downgrade -1` twice | Both revisions apply and reverse independently. |

Two notes on how these are invoked, because the scope changes the result:

- **The `-r <manifest>` argument to `pip-audit` is mandatory.** A bare invocation audits
  the whole active environment and conflates the audit tool's own dependency tree with the
  application's, inflating the count and obscuring which findings the application owns.
  The runtime and development manifests are audited separately for the same reason.
- **Bandit's scope is deliberately `backend/app` and not the whole `backend/` tree.**
  Including the test directory adds a large volume of assertion-related low-severity
  findings that do not breach the Medium threshold but do bury real signal.

Two guards keep the accepted residual risk honest as the code changes. Both are wired
into continuous integration:

```bash
# The omitted package must stay omitted, or six advisories return.
! pip show python-multipart

# The residual advisories must stay unreachable: zero occurrences across backend/.
! grep -rEn "request\.form|request\.url|StaticFiles|HTTPEndpoint|Route\(|set_key|unset_key|\bclick\b" \
    --include=*.py backend/
```

After migration, **exactly one account holds the `admin` role and every other account
holds `registered`.** The grant lives in its own migration revision, which logs it and
asserts that post-condition; no other code path can write the administrative value.

### Dependency changes

A Python dependency manifest now exists for the first time:
[`backend/requirements.txt`](backend/requirements.txt) for the runtime and
[`backend/requirements-dev.txt`](backend/requirements-dev.txt) for verification tooling.
Nothing in the development manifest enters the runtime image.

Four packages were replaced rather than upgraded, and one was omitted:

| Removed | Replaced by |
| --- | --- |
| `python-jose[cryptography]` | `PyJWT[crypto]` 2.13.0 |
| `passlib[bcrypt]` | `bcrypt` 5.0.0, called directly |
| `paypalrestsdk` | `httpx` 0.28.1 against the PayPal REST API |
| `requests` | `httpx` — its single call site moved |
| `python-multipart` | Omitted entirely; it was never imported. |

Two packages were added:

| Added | Purpose |
| --- | --- |
| `alembic` 1.16.5 | Schema migrations. No migration framework existed before. |
| `slowapi` 0.1.10 | Rate limiting on the credential and webhook endpoints. |

Measured outcome: **dependency advisories fall from 19 across 7 packages to 7 across 3
packages.** Removing `python-jose` and `requests` also removes `ecdsa`, `rsa`, `pyasn1`
and `urllib3` from the runtime graph.

The seven remaining advisories are **accepted residual risk**: every available fix
requires Python 3.10 or later, which the runtime pin forecloses. Each carries a named
compensating control, and the register with the supporting evidence is at
[`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md).

Existing `$2b$` and `$2a$` password hashes continue to verify, so **there are no forced
password resets**; passwords are capped at 72 bytes and a longer one is refused with a
validation error. Rationale for each replacement, and for the hash-compatibility
approach, is in [`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md).

### Frozen interfaces

These are guarantees about what did **not** change. Where a bound was added, the addition
is named alongside the guarantee it sits under.

- **The login response shape is unchanged:** `{"access_token": ..., "token_type":
  "bearer"}`. Fields may be added; none were removed. The registration response keeps its
  nested `user` object alongside them.
- **All four router prefixes are unchanged:** `/auth`, `/listings`, `/filters`,
  `/subscriptions`.
- **All eight existing route method-and-path pairs are unchanged:** `POST /auth/register`,
  `POST /auth/login`, `GET /listings/`, `POST /listings/`, `POST /filters/`,
  `GET /filters/`, `POST /subscriptions/`, `GET /subscriptions/`. One route is added:
  `POST /subscriptions/webhook`, mounted under the existing prefix.
- **`GET /listings/` remains publicly reachable without authentication.** Its pagination
  is now bounded by `MAX_PAGE_SIZE` and `MAX_PAGINATION_OFFSET`.
- **The filter endpoints' ownership scoping is unchanged.**
- Every stored password hash remains verifiable.

### Breaking change: `POST /listings/` now requires the `admin` role

> **This is the one intentional breaking change in this release.** `POST /listings/` moves
> from *reachable by any authenticated account* to **administrators only**. A caller
> holding any other role now receives an authorization denial.

**Why it is necessary.** The endpoint writes to the shared listing corpus every user of
the service reads, and registration is self-service, so any account could inject or
manipulate corpus content; no configuration change or input validation closes an
authorization gap.

**Measured blast radius.** No frontend source calls this endpoint, and the corpus is
populated by the background ingestion task, which writes through the ORM rather than
through the HTTP route — so the ingestion workflow is unaffected. The practical impact is
limited to any external or operational client not present in this repository.

**What a consumer must do.** Call the endpoint with a token belonging to an account that
holds the `admin` role. A deployment that needs corpus writes from a non-administrative
operator must grant that operator the role deliberately.

[`docs/review/CRITICAL_DECISIONS.md`](docs/review/CRITICAL_DECISIONS.md) carries the
reviewer checks for this change, including confirmation that every non-frontend consumer
has been identified and notified. The alternatives that were considered and rejected are
recorded in [`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md).

Alongside it, role-based access control now applies across the routing surface. The model
is an ordered `guest` / `registered` / `premium` / `admin` scale that **denies by
default**: an absent, unrecognised, differently cased or whitespace-padded role satisfies
no minimum and the request is refused before any rank comparison. **Roles are resolved
from the database row loaded during authentication, never from a token claim** — the
token's role claim exists for observability only, and every denial is logged with the
required, effective and claimed role.

## Usage Guide

The application API is the eight pre-existing routes plus the webhook listener. The two
health endpoints sit outside the API router.

| Method and path | Access |
| --- | --- |
| `POST /auth/register` | Public. Rate-limited. |
| `POST /auth/login` | Public. Rate-limited, with a per-account lockout after repeated failures. |
| `GET /listings/` | **Public — no token required.** Pagination is bounded. |
| `POST /listings/` | **`admin` only.** See [Breaking change](#breaking-change-post-listings-now-requires-the-admin-role). |
| `POST /filters/` | Authenticated. Scoped to the calling account. |
| `GET /filters/` | Authenticated. Returns only the caller's filters. |
| `POST /subscriptions/` | Authenticated. Accepts a `plan_id` only. |
| `GET /subscriptions/` | Authenticated. Returns only the caller's own row. |
| `POST /subscriptions/webhook` | Unauthenticated by necessity; accepted only with a valid PayPal signature. |
| `GET /health`, `GET /health/ready` | Public liveness and readiness. |

A typical flow: register or log in, read the token from the login response, browse
`GET /listings/`, save a filter, then subscribe by posting a `plan_id`.

Two properties of the subscription flow are worth stating explicitly:

- **The charge amount and the entitlement dates are server-owned.** `POST /subscriptions/`
  accepts a `plan_id` and nothing else. The amount, currency and period come from the
  server-side plan catalog and the entitlement dates from the server clock, so no field a
  client can send influences what is charged or what access is granted.
- **The PayPal hosted redirect is retained, so no card number enters or is stored by this
  service.** Payment handling here operates on order identifiers, plan identifiers and
  webhook notifications only.

## Project Structure

```text
apartment-finder-service/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── endpoints/          auth, listings, filters, subscriptions
│   │   │   └── router.py           the four router prefixes (frozen)
│   │   ├── core/                   config, security, authorization, plans, logging, rate_limit
│   │   ├── db/                     engine and session, ORM models
│   │   ├── schema/                 user, listing, filter, subscription contracts
│   │   ├── services/               paypal, zillow, email
│   │   ├── tasks/                  listing ingestion
│   │   └── main.py                 app assembly, middleware, health endpoints
│   ├── migrations/
│   │   └── versions/               0001 additive schema, 0002 single-admin seed
│   ├── tests/
│   │   └── security/               the security suite
│   ├── alembic.ini
│   ├── requirements.txt
│   └── requirements-dev.txt
├── frontend/
│   └── src/                        React and TypeScript client
├── infrastructure/
│   ├── docker/                     backend and frontend images, compose stack
│   └── terraform/                  Google Cloud infrastructure
├── scripts/                        deployment and local setup
├── docs/
│   ├── security/                   decision log, traceability, residual risk, rotation
│   └── review/                     critical decision review
├── blitzy-deck/                    executive summary presentation
├── documentation/                  product and design specifications
├── .env.example
├── .dockerignore
├── .gitignore
├── setup.cfg                       flake8, pytest and coverage configuration
├── SECURITY.md
└── README.md
```

## Technologies Used

**Backend runtime.** CPython 3.9 · FastAPI 0.125.0 · Starlette 0.49.3 · Pydantic 1.10.26 ·
SQLAlchemy 1.4.54 · Alembic 1.16.5 · PostgreSQL 13 via psycopg2-binary 2.9.12 ·
Uvicorn 0.39.0 · slowapi 0.1.10.

**Security primitives.** PyJWT 2.13.0 with the `crypto` extra · bcrypt 5.0.0 called
directly · `cryptography` 50.0.0.

**Integrations.** httpx 0.28.1 for every outbound call, including the PayPal REST API and
the Zillow listing endpoint · SendGrid 6.12.5 for transactional email.

**Verification tooling.** pytest with pytest-asyncio and pytest-cov · pip-audit · Bandit ·
flake8.

**Frontend.** React with TypeScript.

Three pins are deliberate and are not staleness:

- **Pydantic is held at 1.10.26** and **SQLAlchemy at 1.4.54.** Neither carries an
  advisory, and both are frozen on purpose.
- **FastAPI is pinned at 0.125.0 because that is the highest release compatible with
  Pydantic v1.** Every later release requires Pydantic v2.

The reasoning for each is in
[`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md).

## Security Documentation

| Document | What it holds |
| --- | --- |
| [`SECURITY.md`](SECURITY.md) | Vulnerability disclosure policy, supported versions, and scope. |
| [`.env.example`](.env.example) | The complete configuration contract. |
| [`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md) | Every non-trivial decision, the alternatives that existed, and the risk each carries. This is the single source of truth for *why*. |
| [`docs/security/TRACEABILITY_MATRIX.md`](docs/security/TRACEABILITY_MATRIX.md) | The bidirectional mapping from finding, to the file that fixes it, to the test that verifies it. |
| [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) | The seven accepted advisories, their unreachable fix versions, and each named compensating control. |
| [`docs/security/CREDENTIAL_ROTATION.md`](docs/security/CREDENTIAL_ROTATION.md) | The ordered runbook for credentials exposed through version control. |
| [`docs/review/CRITICAL_DECISIONS.md`](docs/review/CRITICAL_DECISIONS.md) | The five highest-risk decisions, each with its reviewer persona and that reviewer's checks. |
| `blitzy-deck/executive-summary.html` | Executive summary presentation, for a non-technical audience. Open it directly in a browser. |

Some findings discovered during this work were **reported and are awaiting confirmation
rather than fixed**, because remediating them falls outside the agreed scope. They are
listed under *Reported but Unresolved Findings* in [`SECURITY.md`](SECURITY.md).

## Contributing Guidelines

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch-name`
3. Make your changes and commit them: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature-branch-name`
5. Submit a pull request.

Before opening a pull request, run every command in [Verification](#verification). Those
same gates run in continuous integration, which additionally enforces the two
compensating-control guards, so a change that makes an accepted residual advisory
reachable fails the build.

Two conventions apply to contributions that touch security-relevant code:

- **Rationale belongs in [`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md),
  not in code comments.** A comment may state what a control does; why that approach was
  chosen over another goes in the decision log.
- Do not advance the Python version. See
  [System Requirements](#system-requirements).

## License

This project is licensed under the MIT License.

## Contact Information

For questions about the project, contact the maintainer:

- Name: Your Name
- Email: your.email@example.com
- GitHub: [Your GitHub Profile](https://github.com/your-username)

The values above are placeholders; replace them with real contact details before relying
on them.

**Do not report a suspected vulnerability through these channels or in a public issue.**
Use the private reporting process in [`SECURITY.md`](SECURITY.md) instead.
