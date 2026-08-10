# Apartment Finder Service

An apartment-listing discovery service. A background ingestion task queries a Zillow
listing endpoint and persists the results, and an end-user API exposes authentication,
the listing corpus, user-owned saved filters, and premium subscriptions paid through
PayPal. The backend is Python 3.9 with FastAPI, SQLAlchemy and PostgreSQL.

A React client exists in `frontend/`, but **frontend integration is currently
non-operational and separately scoped.** The client cannot presently consume this API: it
calls a different authentication route and reads a login-response field the backend does not
return, omits the `Authorization` header on protected calls, and integrates PayPal through a
different product contract. These defects predate the current hardening work and were not
introduced by it, and `frontend/` was read-only for that work — so they are reported rather
than patched, and none of them is a weakness in the service. Repair belongs to an authorized
frontend change; the hardened backend contracts will not be relaxed to accommodate the
client. The API is fully usable without it, as [Verification](#verification) shows.

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
| Node.js | 14 in the image, as pinned by `infrastructure/docker/Dockerfile.frontend`; 22 in continuous integration | Only for the `frontend/` workspace; not needed to run the API. The `frontend` CI job installs the committed lockfile, which is `lockfileVersion: 3` and needs a Node major the image's npm cannot supply, then lints `src/` directly — `frontend/package.json` declares no `lint` script and is read-only here — and runs the test command with `--passWithNoTests`, because the workspace carries no test file. The image's major version has reached end of life; that is a reported finding awaiting confirmation, not a resolved one — see [Security Documentation](#security-documentation). |

**The Python 3.9 pin is a hard constraint and is load-bearing in five places:**
`infrastructure/docker/Dockerfile.backend` (`FROM python:3.9-slim`),
`.github/workflows/ci.yml` (`python-version: '3.9'`),
`infrastructure/terraform/main.tf` (`runtime = "python39"`),
`scripts/deploy.sh` (`--runtime python39`), and a decorator in
`backend/app/tasks/listing_updater.py` that a newer interpreter would break. The first
four are version declarations; the fifth is a code-level constraint, and it is the reason
the pin is not merely a preference — `@asyncio.coroutine` was removed in Python 3.11, so
the code itself would stop working. [`SECURITY.md`](SECURITY.md) carries the same five
sites in tabular form, and the two documents are kept in step deliberately.

The third and fourth of those configure a managed-runtime Cloud Function, and that
product no longer offers the pinned interpreter. Neither declaration was removed and
**the pin was not relaxed**: both are held behind an explicit authorization gate —
`var.cloud_function_deployment_authorized` in Terraform, which defaults to `false` and
leaves the function and its invoker binding out of the plan entirely, and
`CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED` in the deployment script, which skips the
corresponding step. The reason is a platform change rather than a choice about the
interpreter, and it is the single most important thing to know before deploying this
service:

> **Deployment-platform notice.** Google retired the Python 3.9 runtime of Cloud
> Functions on **5 April 2026**. After that date a function cannot be created or updated
> on that runtime, and existing deployments on it are liable to be disabled. The pinned
> interpreter therefore **cannot** be hosted on that product, and this repository no
> longer claims it can: the Terraform resource and the deployment step that would create
> such a function are both gated off by default, so no delivery path deploys one unless a
> release owner authorizes it explicitly — at which point a supported runtime has to be
> chosen or the function retired.
>
> **The supported alternative, already in place.** The service runs as containers on GKE
> from `infrastructure/kubernetes/`, on the `python:3.9-slim` backend image — so the pinned
> interpreter is preserved by the image rather than requested from a managed runtime. The
> periodic listing-ingestion workload the retired function nominally carried now runs as
> the CronJob at `infrastructure/kubernetes/65-ingestion-cronjob.yaml`, on that same image.
>
> **One operator action this does not perform.** Deleting the Terraform resource does not
> revoke an IAM binding a previous apply already granted. If a Cloud Function still
> exists in your project, check its invoker role for `allUsers` and
> `allAuthenticatedUsers`; `scripts/deploy.sh` performs that revocation explicitly and
> idempotently, and [`docs/review/CRITICAL_DECISIONS.md`](docs/review/CRITICAL_DECISIONS.md)
> entry 2 assigns the check to a reviewer.

Where a dependency's only available fix requires a newer interpreter, the advisory is
recorded as accepted residual risk instead — see
[`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md), which also carries the
platform notice above with its evidence and its compensating controls.

## Security and Setup

### Environment configuration

All configuration is supplied through environment variables read by
`backend/app/core/config.py`, a Pydantic v1 `BaseSettings` class.
**[`.env.example`](.env.example) is the authoritative catalog of every variable** — its
comments carry the accepted values, defaults and validation rules for each one, so consult
it rather than any list reproduced elsewhere.

**Which file is read.** By default the settings class reads `DEFAULT_ENV_FILE`, which is
`.env` **at the repository root, by absolute path**, computed from `config.py`'s own
location, so the same file is read whichever directory you start the process in. `ENV_FILE` is itself read from the process
environment and is not a setting; it overrides that default, and its three states are
distinct:

| `ENV_FILE` | File read |
| --- | --- |
| Not set | `DEFAULT_ENV_FILE` — `<repository root>/.env` |
| Set to a path | That path, used exactly as given. A relative value resolves against the current working directory |
| Set but empty | **No file at all.** Every setting must then come from the process environment — this is how the test suite isolates itself |

A process environment variable always takes precedence over the same name in the file.
Stated as prose, because the distinction is easy to lose in a table: `ENV_FILE` in the
process environment overrides that default: set it to a path and that file is read
instead &mdash; a relative path there is resolved against the working directory &mdash;
and set it to an empty value to read no file at all, which is the form to use when every
setting arrives from the process environment. `ENV_FILE` is not itself a setting and must
not appear as a line inside the file.

Bootstrap. The supported route is the setup script, which is the only one that
produces a `.env` the application will start against without further editing:

```bash
./scripts/setup_dev_environment.sh
```

It writes `.env` from the template with mode 0600, generates a `SECRET_KEY` that
clears every validation rule and an `ADMIN_SEED_PASSWORD`, prompts for the database
password and percent-encodes it into `DATABASE_URL`, creates the role and database,
applies both migrations, and seeds the single administrator. **No generated value is
printed** — the script reports the administrator by a non-reversible twelve-character
reference, the same one migration `0002` records.

`.env` is untracked and holds real secrets once it is filled in, so it must never
be replaced by the template. Prefer `scripts/setup_dev_environment.sh`, which keeps an
existing `.env`, checks that it already carries a configured `DATABASE_URL`, and creates
the file only when it is absent &mdash; with mode `600`, a generated signing key and a
generated administrator password. To create it by hand, guard the copy explicitly:

```bash
if [ -e .env ]; then
  echo ".env already exists; leaving it untouched." >&2
else
  ( umask 077; cp .env.example .env )
fi
```

A bare `cp .env.example .env` is the wrong command here: it silently replaces a
secret-bearing file and exits 0.

**Then generate a real signing key.** The template's `SECRET_KEY` is a placeholder on
the startup denylist and is refused in every environment, so it has to be replaced
before the application will start. Generate the replacement **into** the file. Do not
generate it through the terminal: a signing key printed to stdout is retained by
scrollback, shell history, CI logs and support transcripts, and a signing key that
leaked once is exactly the exposure this repository is remediating.

```bash
( umask 077
  python - <<'PY'
import pathlib
import re
import secrets

path = pathlib.Path(".env")
value = secrets.token_urlsafe(48)  # never printed; the umask 077 above
path.write_text(                   # keeps .env readable only by its owner
    re.sub(r"(?m)^SECRET_KEY=.*$", "SECRET_KEY=" + value, path.read_text())
)
PY
)
```

Confirm the result by a property of the value rather than by displaying it, then let
startup be the real check:

```bash
awk -F= '/^SECRET_KEY=/ { print length($2) " characters written" }' .env
python -c "import backend.app.main"
```

The same rule applies to every other secret-bearing entry: write it into `.env`,
and never echo it.

Five further values still need real provisioning before the integrations they configure
will work: `ZILLOW_API_KEY`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`,
`PAYPAL_WEBHOOK_ID` and `SENDGRID_API_KEY`. Neither route can supply them. Until they
are supplied they hold the template's placeholders, which are accepted only while
`ENVIRONMENT=local`, so the application starts with those integrations non-functional.


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

**Every command in this section runs from the repository root.** The packages resolve as
implicit namespace packages with no `__init__.py` anywhere, so the repository root has to
be the working directory for `backend.…` imports to resolve, and `python -m` is what puts
it on `sys.path`.

```bash
python3.9 -m venv .venv && . .venv/bin/activate
python -m pip install --upgrade pip
pip install -r backend/requirements.txt -r backend/requirements-dev.txt
```

**Run every command below from the repository root.** The packages resolve as implicit
namespace packages, so `backend.app.*` imports only work with the repository root on
`sys.path` — which is where you already are if you have not changed directory. The
commands are written so that none of them requires you to.

Apply the schema with Alembic:

```bash
alembic -c backend/alembic.ini upgrade head
```

The `-c` form is used rather than `cd backend` precisely so the shell stays at the
repository root for the next command. `backend/alembic.ini` resolves its script location
relative to its own path, so it works from anywhere.

**The schema is now owned by migrations.** The `Base.metadata.create_all` call that ran
at application import time has been removed. **Migrations must run before the new code
serves traffic**, because the authorization dependency reads a column the migration adds.
Every column revision `0001` adds carries a server default, and its downgrade reverses
whichever path was taken: on a database it created the tables in, it drops exactly those
tables, and on a database that already held them, it reverses only the columns it added and
leaves the pre-existing tables in place.

Give the seeded administrator a credential:

```bash
ADMIN_SEED_PASSWORD='<a password satisfying the account policy>' \
  python -m backend.app.core.admin_provisioning
```

**This step is required before the administrator can sign in, and it is separate from
the migration on purpose.** Revision `0002` grants the administrative role to
`test@blitzy.com` and stores `!locked-no-password-set`, which is not a hash any password
produces — so the account holds the role and cannot authenticate until this command runs.
No credential is embedded in a migration, in a manifest or in this repository.

The command reads the credential only from `ADMIN_SEED_PASSWORD`, never from an argument,
so it does not reach a shell history or a process listing. It holds that credential to the
same policy every account is held to: at least 12 characters, at most 72 UTF-8 bytes, and
an uppercase letter, a lowercase letter, a digit and a special character. It writes only to
`test@blitzy.com`, refuses an account that does not already hold the role — so it is not a
privilege-escalation path — and re-asserts that exactly one account holds the role before
committing. It records the outcome and the administrator count through the redacting
logger, and no record carries the credential.

Running it again is safe. A credential already in place is left alone, and the command
reports `unchanged`. To replace one deliberately, set `ADMIN_CREDENTIAL_RESET=true`;
[`docs/security/CREDENTIAL_ROTATION.md`](docs/security/CREDENTIAL_ROTATION.md) records when
that is appropriate.

In a deployed environment the same command runs as
[`infrastructure/kubernetes/70-admin-credential-job.yaml`](infrastructure/kubernetes/70-admin-credential-job.yaml),
which receives the credential from Secret Manager under its own least-privilege identity,
so the serving workload never mounts it. It is an operator step rather than part of a
release: it is absent from the renderer's `all` group, and both deployment paths skip it
unless asked. Set `PROVISION_ADMIN_CREDENTIAL=true` for `scripts/deploy.sh`, or the
repository variable of the same name for the CD workflow.

Run the server:

```bash
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Liveness is at `GET /health`; readiness, which answers 503 while the database is
unreachable, is at `GET /health/ready`.
Run it from the repository root: the packages resolve as implicit namespace packages, and
the module path is `backend.app.main:app`.

Two probes are served. **Liveness at `GET /health`** answers 200 unconditionally and reads
nothing, so it reports that the process is up and nothing more. **Readiness at
`GET /health/ready`** reads the database and answers 503 while it is unreachable, which is
what makes it the useful probe for a rollout.

Because readiness is public and does touch the database, the work it can cause is bounded
three ways, each tunable in `.env.example`:

- One outcome is reused for `READINESS_CACHE_SECONDS` (5.0 by default), so a burst of
  callers costs one database read rather than one each, and only one caller at a time is
  admitted to that read.
- Its read carries `READINESS_TIMEOUT_SECONDS` (2.0) as a transaction-local statement and
  lock timeout, so a stalled database fails the probe quickly instead of holding it open.
  The bound is set with `set_config(..., true)`, so it applies to that transaction alone
  and never to a migration.
- It is rate limited at `RATE_LIMIT_READINESS` (60/minute), and answers 429 beyond that.

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

Both profiles also run a `cache` service, which is the store the rate limiter shares its
counters through. It publishes no port and persists nothing, and the backend waits for it
to report healthy. `ENVIRONMENT=local` is the only setting under which the application
accepts an in-process store, so a stack configured for any other environment must point
`RATE_LIMIT_STORAGE_URI` at a shared store — `redis://cache:6379/0` addresses this one.

The backend image **runs as a non-root user**, and the **published port is aligned to
8000**, which is the port the image exposes and the port the health check probes.

### Inputs an operator must supply

The hardening in this work moved several values out of source and into inputs that have to
be provided per environment. Each is listed here because a missing one is a startup or
deployment failure rather than a silent default, which is deliberate — a security setting
that quietly defaults is a security setting nobody notices is wrong.

**Compose — ten variables have no default and must be supplied.** The stack refuses to
start and names the missing variable:

```text
BACKEND_ENVIRONMENT                 CLOUD_SQL_INSTANCE_CONNECTION_NAME
COMPOSE_DATABASE_URL                POSTGRES_PASSWORD
SECRET_KEY                          ZILLOW_API_KEY
PAYPAL_CLIENT_ID                    PAYPAL_CLIENT_SECRET
PAYPAL_WEBHOOK_ID                   SENDGRID_API_KEY
```

`BACKEND_ENVIRONMENT` is required rather than defaulted so that a container cannot inherit
`local` semantics by omission. `CLOUD_SQL_INSTANCE_CONNECTION_NAME` is consumed only by the
`gcp` profile's proxy, and is validated to be well formed under that profile.

**Deployment workflow — four repository secrets and five repository variables.**
`.github/workflows/cd.yml` reads these and asserts every one is present and well formed
before it mutates anything. Only the four in the first table are credentials or
project identifiers; the rest are configuration, so they are repository variables:

| Secret | Purpose |
| --- | --- |
| `GCP_PROJECT_ID` | The target project. |
| `GCP_WORKLOAD_IDENTITY_PROVIDER`, `GCP_SERVICE_ACCOUNT` | Federated identity, which replaced the long-lived service-account key. |
| `GKE_CLUSTER_NAME` | The cluster the rollout targets. |

| Variable | Purpose |
| --- | --- |
| `GKE_CLUSTER_REGION` | The cluster's region, addressed **regionally**. This replaces a zonal setting: a regional cluster cannot be reached with a zone flag, and the former `GKE_CLUSTER_ZONE` secret is retired. |
| `K8S_NAMESPACE` | The namespace whose workloads are updated. |
| `ARTIFACT_REGISTRY_LOCATION`, `ARTIFACT_REGISTRY_REPOSITORY` | The regional registry images are pushed to and pulled from, replacing `gcr.io`. |
| `GKE_DEPLOY_RUNNER_LABEL` | The self-hosted runner inside the VPC that the deploy job runs on. |

**Terraform — inputs with no safe default.** Beyond `project_id` and the six secret values,
the resources added by this work require `database_private_network`,
`gke_master_authorized_networks`, `cloud_function_invoker_member`, `github_repository`
(which scopes federated identity to one repository, and is what stops any repository
minting a token for this project), `cloud_function_entry_point` and
`cloud_function_source_archive`.

**Backend settings added for boundary resilience.** Each has a working default, and one of
them needs deliberate attention per deployment:

| Setting | Effect |
| --- | --- |
| `DB_CONNECT_TIMEOUT_SECONDS` | Caps how long a new database connection may take to establish. |
| `DB_POOL_TIMEOUT_SECONDS` | Caps how long a request waits for a pooled connection. |
| `DB_POOL_RECYCLE_SECONDS` | Retires connections before an idle peer can drop them. |
| `TRUSTED_PROXY_HOPS` | **Set this to the real number of proxies in front of the service.** It defaults to `0`, meaning no forwarded client address is trusted. Behind a GKE ingress or load balancer the default makes rate limits and lockouts apply per proxy rather than per client, which is the safe direction to be wrong in but is not what you want. |

**Two behaviour changes worth knowing before you deploy.** Email delivery now treats only
HTTP 202 from SendGrid as success, where any 2xx previously passed. And a non-local
`ENVIRONMENT` requires `SECRET_BACKEND=gcp-secret-manager`; the value `env` is accepted only
when `ENVIRONMENT` is `local`.

**Correlating a request across systems.** One log record carries `request_id` alongside the
provider's own `provider_order_id` and `paypal_debug_id`, so a payment can be joined to
PayPal's records deterministically rather than by timestamp. Outbound Zillow calls carry the
same identifier in an `X-Request-ID` header.

### Deploying to Google Cloud

Two paths reach a cluster: `.github/workflows/cd.yml` on a push to `main`, and
`scripts/deploy.sh` by hand. `backend/tests/security/test_release_contract.py` and
`backend/tests/security/test_release_path_contract.py` hold the two to one agreement, so a
Dockerfile path, workload name, registry prefix or function name that drifts in one of them
fails the suite. **They address one inventory, one registry and one Cloud
Function**, and each asserts that what it is about to change exists before it changes
anything.

| Contract | Value |
| --- | --- |
| Deployments rolled | `backend` and `frontend`, each running a single container of the same name |
| Image definitions | `infrastructure/docker/Dockerfile.backend` with context `backend/`, `infrastructure/docker/Dockerfile.frontend` with context `frontend/` &mdash; both named explicitly, because neither context holds a `Dockerfile` |
| Registry | `${GKE_REGION}-docker.pkg.dev/${PROJECT}/${ARTIFACT_REGISTRY_REPOSITORY}/<workload>`, provisioned by Terraform with `immutable_tags = true`. Container Registry (`gcr.io`) is not used and cannot be: it was shut down for writes |
| Release identity | An immutable tag per release. **A tag that already exists is refused**, and the rollout is applied by digest, then the running pod's `imageID` is compared against it |
| Migrations | A bounded one-shot pod built from the release image, run **before** the rollout and required to succeed first |
| Cluster access | A regional cluster addressed with `--region`, reached over the authorized DNS endpoint while the private endpoint stays private. Requires `container.clusters.connect` |
| Cloud Function | `apartment-finder-probe`, entry point `hello_world`, runtime `python39`, source `function-source.zip` in the project's static-assets bucket, invoker restricted &mdash; no anonymous invocation |

The pipeline needs two repository **secrets** (`GCP_PROJECT_ID`, `GKE_CLUSTER_NAME`) plus
the two Workload Identity Federation secrets (`GCP_WORKLOAD_IDENTITY_PROVIDER`,
`GCP_SERVICE_ACCOUNT`), and three repository **variables**, which are not credentials:
`GKE_CLUSTER_REGION`, `K8S_NAMESPACE` and `ARTIFACT_REGISTRY_REPOSITORY`. **The former
`GKE_CLUSTER_ZONE` secret is retired**, because the cluster is regional. `deploy.sh`
takes no arguments and reads `GCP_PROJECT_ID`, `GKE_CLUSTER`, `GKE_REGION`,
`K8S_NAMESPACE` and `VERSION` from the environment; run `scripts/deploy.sh --help` for
the full contract. It additionally needs `jq` and `timeout` on `PATH`.

Terraform requires eleven variables with no default, including
`artifact_registry_writer_members`, `secret_accessor_members`,
`cloud_function_invoker_member` and `database_private_network`. The six application
secrets are provisioned as Secret Manager secrets whose `secret_id` is the setting name
that consumes it, with a per-secret `roles/secretmanager.secretAccessor` binding for the
workload principal.

**Two things block a first release, deliberately and visibly rather than silently:**

- **The Cloud Function runtime.** `python39` is decommissioned for create and update, and
  the pin is a hard constraint of this work that must not be advanced. Both the Terraform
  resource and the script step are therefore gated behind an explicit owner
  authorization &mdash; `var.cloud_function_deployment_authorized` and
  `CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED` &mdash; which default to off. Until an owner
  decides, the function is left out of the plan and the step reports itself blocked
  instead of failing the release or weakening the pin.
- **The Kubernetes objects the release updates are declared here but applied by an
  operator.** `scripts/render_kubernetes_manifests.sh` renders them from the committed
  sources, and both release paths verify that the `backend` and `frontend` Deployments and
  the container inside each already exist before changing anything. Nothing is created
  implicitly, and the migration workload asserts it received its settings rather than
  assuming it. A missing object stops the release naming what is missing.


### Verification

These are the measurable gates for this work. Run them from the repository root with the
virtual environment active. **The set is wider than what continuous integration runs**, so
the last column says where each gate executes — a local pass is not the same evidence as a
pipeline pass, and neither substitutes for the other.

**Locally runnable is not the same as enforced on every change.** A command the *Enforced
by* column marks **Enforced** runs in `.github/workflows/ci.yml` on every push and every
pull request to `main`, and the deployment workflow calls that same workflow rather than
reimplementing part of it, so nothing reaches an environment without passing it. A command
marked *Local only* is available to you and blocks nothing. The `Integration gate` job is
the one that exercises the running service, and it is enforced.

The **Enforced by** column states what actually fails when a command fails, and it is not
decoration. An earlier version of this section claimed that every command below runs in
continuous integration when several did not, and the integration gate was a step
containing comments only, which always succeeded. Both are corrected: the column names the
CI job that runs each command, or says plainly that nothing but you runs it.

| Command | Expected result | Enforced by |
| --- | --- | --- |
| `python -c "import backend.app.main"` | Exit code 0 — the application imports. | **CI — `integration` job**, step "Verify the application starts" |
| `python -m pytest backend/tests -q` | Tests collected, all passing. | **CI — `backend` job**, which runs the same suite with coverage instead of `-q` |
| `python -m pytest backend/tests/security -q` | All passing, including the **45-assertion role matrix** — nine role-governed routes by five principals, anonymous included. | **CI — `backend` job**, this exact command |
| `pip-audit -r backend/requirements.txt` | **Only** the seven advisories in the *Runtime register* of [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md). | **CI — `backend` job**, as `--strict` with those seven identifiers suppressed by name, so an eighth fails the build |
| `pip-audit -r backend/requirements-dev.txt` | **Only** the seven advisories in the *Development register* of the same file. Fourteen identifiers are suppressed in total, all of them registered. | **CI — `backend` job**, the same way, with that manifest's seven identifiers |
| `bandit -r backend/app -ll` | Exit code 0 — no Medium or High findings. | **CI — `backend` job**, this exact command |
| `flake8 backend` | Clean. | **CI — `backend` job**, which runs `flake8 .` from inside `backend/`. Same files, and the per-file ignores in `setup.cfg` are written to match under both spellings |
| `cd infrastructure/terraform && terraform init -backend=false && terraform validate` | Passes. | **CI — `infrastructure` job**, which additionally runs `terraform fmt -check -recursive` before validating |
| `cd backend && alembic upgrade head` | Every revision applies; `alembic current` reports `0003 (head)`. |
| Reversibility, **against a disposable database only**: `alembic upgrade head`, `alembic downgrade -1`, `alembic downgrade -1`, `alembic upgrade head`, `alembic current` | Each revision reverses independently and re-applies, and the sequence **ends at `0003 (head)`**. | **CI — `integration` job**, against a PostgreSQL 13 service, which also reapplies afterwards and asserts exactly one administrator |
| `bash -n scripts/deploy.sh scripts/render_kubernetes_manifests.sh` | Exit code 0. | **Manual / local only.** No CI job parses the deployment scripts |
| `kubectl create --dry-run=client -f <rendered manifest>` | Accepted for every built-in kind. | **Partly CI.** The `infrastructure` job checks the manifests against the settings contract — key sets, the secret backend, no literal secret, no inline environment entry — but does **not** run a client-side schema validation, which needs `kubectl` |
| Opening `blitzy-deck/executive-summary.html` in a browser | Renders; every section carries a non-text visual. | **Manual / local only** |
| The credential rotation runbook | Each step completed in order. | **Manual / operational only**, and irreversible. See [`docs/security/CREDENTIAL_ROTATION.md`](docs/security/CREDENTIAL_ROTATION.md) |

**Continuous integration runs six jobs** — `backend`, `runtime-integration`,
`postgres-integration`, `integration`, `frontend` and `infrastructure`. Four of them
declare no dependency at all, so a failure in one cannot prevent their gates from running
and reporting. That independence is deliberate where it matters most: the frontend checks
previously sat ahead of the security gates *inside* the backend job, so a frontend failure
stopped the dependency audit, the static analysis and the security suite from running at
all. They are now a job of their own with no dependants. The two integration jobs that do
declare `needs: backend` do so on purpose — there is nothing to learn from migrating a
database and serving the application when the unit suite has already failed. The
workflow's overall conclusion is success only when all six pass, and that conclusion is
what the deployment workflow gates on.

**What each job runs.** One row per job, so a gate can be traced to the thing that fails
when it fails:

| Job | What it runs |
| --- | --- |
| `backend` | `flake8 .` from inside `backend/`, both `pip-audit --strict` invocations, `bandit`, the two compensating-control guards, the secret and ignore policy, the import gate, the migration round trip, the administrator-count assertion, the unit suite with coverage and the security suite |
| `runtime-integration` | Applies the revisions, reverses and reapplies them, asserts the administrator count, verifies the import, then serves the application and exercises it over HTTP |
| `postgres-integration` | Reports the database version and runs the PostgreSQL migration and persistence suite against a real service |
| `integration` | Applies the migrations, confirms exactly one administrator, starts the API and probes liveness, readiness, the public listing read, and registration, login and the role refusal |
| `frontend` | Installs the declared dependencies, runs ESLint over `src`, and runs the frontend unit tests |
| `infrastructure` | `terraform fmt -check -recursive`, `terraform validate`, and the deployment-manifest settings contract |

**What CI runs that is not in the table above:** the frontend lint job, the frontend unit
tests, the two compensating-control guards below, and both dependency audits in their
strict form. `.github/workflows/ci.yml` is the authority.

Three notes on how these are invoked, because the scope and the flags change the result:

- **The two `alembic downgrade -1` calls are destructive and must not be run against a
  database you intend to keep.** Together they remove the revision that adds the `role`
  column and the revision that seeds the single administrator, so an environment left in
  that state has no authorization data at all &mdash; and every command in the sequence
  exits 0 while doing it. Run the reversibility check against a throwaway database, and
  end it at `alembic upgrade head` with `alembic current` confirming `0003 (head)`.
  Reversibility is a property worth proving, but proving it is not a maintenance
  operation.
- **The plain `pip-audit -r <manifest>` form is diagnostic, not a pass/fail gate.** It
  exits non-zero because the accepted residual advisories are still reported. The pipeline
  gate is `pip-audit --strict -r <manifest>` with each accepted advisory suppressed by
  identifier; that form exits 0, and an eighth finding fails it. Both invocations are
  reproduced in [`SECURITY.md`](SECURITY.md). Compare any plain-form output against
  [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) before treating a
  failure as a regression.
- **The `-r <manifest>` argument is mandatory in either form.** A bare invocation audits

  the whole active environment and conflates the audit tool's own dependency tree with the
  application's, inflating the count and obscuring which findings the application owns.
  The runtime and development manifests are audited separately for the same reason.
- **Bandit's scope is deliberately `backend/app` and not the whole `backend/` tree.**
  Including the test directory adds a large volume of assertion-related low-severity
  findings that do not breach the Medium threshold but do bury real signal.

Two guards keep the accepted residual risk honest as the code changes. Both are wired
into continuous integration, and both are narrower than they look — between them they
assert that one named package is absent and that eight named patterns do not appear in
Python files under `backend/`, and nothing more:

```bash
# Guard 1. The omitted package must stay omitted, or six advisories return.
! pip show python-multipart

# Guard 2, layer 1. A textual pre-filter over the application package — the only
# code a request reaches. Scoped to backend/app/ and not backend/, so a test that
# merely names one of these literals cannot fail the build.
! grep -rEn "request\.form|request\.url|StaticFiles|HTTPEndpoint|Route\(|set_key|unset_key|\bclick\b" \
    --include=*.py backend/app/

# Guard 2, layer 2. The semantic check, run by the security suite above.
python -m pytest backend/tests/security/test_residual_risk_guards.py -q
```

After migration, **exactly one account holds the `admin` role — `test@blitzy.com` — and
the revision preserves every other account's role rather than normalising it.** Revision
`0001` gives `users.role` a server default of `registered`, so accounts that predate the
column land there; revision `0002` then promotes only the target address and touches no
other row, so an account already holding `premium` or `guest` keeps it. The grant lives in
its own revision, which logs it and asserts the one-administrator post-condition; no other
code path can write the administrative value, and
[`backend/app/core/admin_provisioning.py`](backend/app/core/admin_provisioning.py)
re-asserts the same post-condition before it commits.

**The reachability guard has two layers, and the first one is bypassable.** Layer 1 is the
grep above: a textual pre-filter, scoped to `backend/app/` because that is the code whose
reachability the accepted advisories are argued from. It answers in milliseconds and it is
the layer that catches a careless reintroduction. It is also defeated by any spelling the
pattern does not carry — an alias, an attribute reached through `getattr`, an import under
another name — so on its own it would be a guard that reads as stronger than it is.

Layer 2 is `backend/tests/security/test_residual_risk_guards.py`, which resolves the
question semantically: it walks the application's own import graph and abstract syntax
trees rather than its characters, so a construct reintroduced under a different name is
still found. Layer 1 fails fast on the obvious case; layer 2 is the one the acceptance in
[`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) actually rests on. Both
run in `.github/workflows/ci.yml`, and neither is a substitute for the other.

**On the tolerated job.** No job in this pipeline is tolerated. An earlier revision ran
frontend checks as a job marked `continue-on-error: true` and described in both documents
as `Frontend checks (known blocker, gates nothing)`, because the read-only frontend source
could not pass a linter. That job now passes and gates like every other: the linter is
invoked directly with the one unparseable file excluded and recorded as a reported
finding, and the suite runs with `--passWithNoTests` because the workspace carries no test
file. There is therefore no job whose red build a reader should discount.

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

Six new direct pins arrive with those replacements, in three categories:

| Added | Category | Purpose |
| --- | --- | --- |
| `PyJWT[crypto]` 2.13.0 | Replacement | Token signing and verification, in place of `python-jose` |
| `bcrypt` 5.0.0 | Replacement | Password hashing, called directly in place of `passlib` |
| `httpx` 0.28.1 | Replacement | The HTTP client for the PayPal REST API and the Zillow endpoint, in place of `paypalrestsdk` and `requests` |
| `alembic` 1.16.5 | New capability | Schema migrations. No migration framework existed before |
| `slowapi` 0.1.10 | New capability | Rate limiting on the credential and webhook endpoints |
| `limits` 4.2, `redis` 5.3.1 | Transitive, pinned deliberately | `slowapi` delegates its storage to `limits`, and `redis` is the client `limits` needs for every shared rate-limit scheme. Outside `ENVIRONMENT=local` the settings validator **refuses** an in-process store, so a deployable configuration cannot start without them; they are pinned directly rather than left to resolve |

One further pin is new to the manifest without being new to the runtime:

| Newly declared | Why it was already required |
| --- | --- |
| `python-dotenv` 1.2.1 | Pydantic v1 raises `ImportError: python-dotenv is not installed` whenever `env_file` is set, which `config.py` already did before this work. It was an **undeclared** runtime requirement; declaring it documents reality rather than adding a dependency |

`cryptography` 50.0.0 is likewise now pinned explicitly rather than resolved incidentally
through two other packages' extras. The development manifest,
[`backend/requirements-dev.txt`](backend/requirements-dev.txt), additionally declares
`flake8` — which continuous integration invoked but never installed — and `pytest-asyncio`,
which the asynchronous tests require and nothing declared.

Measured outcome: **dependency advisories fall from 19 across 7 packages to 7 across 3
packages.** Removing `python-jose` and `requests` also removes `ecdsa`, `rsa`, `pyasn1`
and `urllib3` from the runtime graph.

The seven remaining runtime advisories are **accepted residual risk**: every available
fix requires Python 3.10 or later, which the runtime pin forecloses — and for the five
in `starlette` a newer interpreter alone would not be enough, because the FastAPI pin
that Pydantic v1 fixes will not accept the releases those fixes occupy. The development
manifest carries **seven more** on the same basis, in test, lint and audit tooling that
no deployed process installs — **fourteen accepted in total**. Each carries a named
compensating control, and both registers with the supporting evidence, the ledger
reconciling all nineteen runtime advisories, and the stated limits of that evidence are
at

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

## Deployment

Deployment is not exercised by this repository's tests and cannot be, so this section is the
contract an operator has to satisfy. Everything below is **new or changed input** that a
deployment configured before this work will not have.

### Repository secrets and variables the workflow reads

`.github/workflows/cd.yml` runs only after `.github/workflows/ci.yml` passes in full — it
calls that workflow rather than repeating part of it — and then reads the following.

| Name | Kind | Note |
| --- | --- | --- |
| `GCP_PROJECT_ID` | secret | Unchanged. |
| `GKE_CLUSTER_NAME` | secret | Unchanged. |
| `GKE_CLUSTER_REGION` | secret | **Renamed.** It replaces `GKE_CLUSTER_ZONE`, and the cluster is regional, so credentials are fetched with `--region` rather than `--zone`. A configuration left on the old name will fail the workflow's input check by design rather than deploying against the wrong location. |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | secret | **New.** Authentication is federated; the long-lived service-account key it replaces must be deleted, not merely unused. |
| `GCP_SERVICE_ACCOUNT` | secret | **New.** The service account the federated identity impersonates. |
| `GKE_DEPLOY_RUNNER` | variable | **New**, defaulting to `self-hosted`. The control plane has a private endpoint with enforcement on, so the job needs a runner with a network path to it. A GitHub-hosted runner cannot reach it. |
| `REACT_APP_API_BASE_URL` | variable | **New.** A frontend build argument, inlined into the bundle and therefore public — never a secret. |
| `PAYPAL_CLIENT_ID` | variable | **New.** The same: a public client identifier, passed as a build argument. The PayPal *secret* is never a build argument. |

### `scripts/deploy.sh`

The script now fails fast rather than proceeding on error, requires `docker`, `gcloud`,
`kubectl` and **`jq`** on `PATH`, and requires these variables:

| Variable | Source |
| --- | --- |
| `GCP_PROJECT_ID`, `VERSION` | The deploying environment. |
| `CLOUD_FUNCTION_NAME` | The `cloud_function_name` Terraform output. |
| `CLOUD_FUNCTION_SOURCE_ARCHIVE` | The `cloud_function_source_archive` output. Must be a `gs://<bucket>/<object>` address; the script confirms the object exists before deploying. |
| `CLOUD_FUNCTION_ENTRY_POINT` | The `cloud_function_entry_point` output. |
| `CLOUD_FUNCTION_REGION` | The region the function is deployed to. |

Taking the function's identity from Terraform's outputs is what stops the two tools
addressing the same function under different names. The function is deployed
`--no-allow-unauthenticated`, and the script then reads its **effective** IAM policy back and
exits non-zero if any public principal remains — an authoritative policy in Terraform removes
an inherited public binding, and this read-back proves it.

Migrations run **before** traffic moves: the Alembic upgrade executes in a one-shot pod built
from the new image, and only if it succeeds does `kubectl set image` roll the Deployment
forward.

### Prerequisites this repository cannot satisfy

| Prerequisite | Why it is not here |
| --- | --- |
| Kubernetes manifests | `deployment/app-deployment`, `deployment/backend` and `deployment/frontend` are addressed by the script and the workflow but defined outside this repository. |
| Secret **delivery** into the pod | Terraform grants the workload identity access to all six secrets and enables the managed Secret Manager add-on, and the `backend_workload_identity_annotation` output gives the exact annotation. Mounting them is a manifest change, so it happens outside this repository. |
| Private services access, and a shared VPC | The Terraform variables enforce that the cluster and the database sit on the same network; the network itself is an input. |

Each is tracked as an operator-owned item at
[`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md) §35.1 rather than being
assumed.


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
| `GET /health` | Public liveness. Answers 200 unconditionally; reads nothing. |
| `GET /health/ready` | Public readiness. Reads the database, 503 when it is unreachable, and bounded by a cached outcome, a statement timeout and a rate limit. |

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
│   │   └── versions/               0001 additive schema, 0002 single-admin seed,
│   │                               0003 workload indexes
│   ├── tests/
│   │   └── security/               the security suite
│   ├── alembic.ini
│   ├── requirements.txt
│   └── requirements-dev.txt
├── frontend/
│   └── src/                        React and TypeScript client
├── infrastructure/
│   ├── docker/                     backend and frontend images, compose stack
│   ├── k8s/                        GKE workloads: deployments, services, config,
│   │                               secret delivery, migration job, ingestion cronjob
│   └── terraform/                  Google Cloud infrastructure
├── scripts/                        deployment, manifest rendering, local setup
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

**Integrations.** httpx 0.28.1 for the PayPal REST API and the Zillow listing endpoint —
those two modules, `paypal_service.py` and `zillow_service.py`, are the only places it is
imported · SendGrid 6.12.5 for transactional email, which uses its **own** client rather
than httpx and carries `python-http-client` as its transport.

An earlier revision of this section claimed httpx was used for *every* outbound call.
It is not, and the distinction matters for one security property in particular: the
guarantee that no outbound request can hang indefinitely is **not** delivered by httpx
alone. The email path obtains it separately, by assigning `settings.HTTP_TIMEOUT_SECONDS`
to the SendGrid client before the send. All three outbound boundaries are therefore bounded
by the same configured timeout, but through two different mechanisms — so a change to
either one has to be checked against both.

**Verification tooling.** pytest with pytest-asyncio and pytest-cov · pip-audit · Bandit ·
flake8.

**Frontend.** React with TypeScript — present in `frontend/`, but not currently operational
against this API, as stated at the top of this file.

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
| [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) | Two registers covering all fourteen accepted advisories &mdash; seven runtime, seven development-only &mdash; with their unreachable fix versions, each named compensating control, and the total-suppression accounting. |
| [`docs/security/CREDENTIAL_ROTATION.md`](docs/security/CREDENTIAL_ROTATION.md) | The ordered runbook for credentials exposed through version control. |
| [`docs/review/CRITICAL_DECISIONS.md`](docs/review/CRITICAL_DECISIONS.md) | The five highest-risk decisions, each with its reviewer persona and that reviewer's checks. |
| `blitzy-deck/executive-summary.html` | Executive summary presentation, for a non-technical audience. Open it directly in a browser. |

Some findings discovered during this work were **reported and are awaiting confirmation or an
operator action rather than fixed**, because remediating them falls outside the agreed scope
or cannot be done from inside a commit. They are published as an itemised inventory — not as
a count — at [`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md) §35.1, which
[`SECURITY.md`](SECURITY.md) points at rather than restating. Several are the operator
prerequisites this file names: a maintainer address and a monitored security mailbox, GitHub
private vulnerability reporting, and the deployment inputs listed under
[Deployment](#deployment).

## Contributing Guidelines

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch-name`
3. Make your changes and commit them: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin feature-branch-name`
5. Submit a pull request.

Before opening a pull request, run every command in [Verification](#verification).
**Continuous integration runs a subset of them, not all of them** — the "Runs in CI?"
column there says which, and the application-import gate, `terraform validate` and the
Alembic downgrade round trip are yours to run locally because nothing else will. CI does
additionally enforce the two compensating-control guards and both dependency audits in
their strict form, so a change that reintroduces the omitted package, or that brings one of
the eight guarded constructs into `backend/`, fails the build.

Two conventions apply to contributions that touch security-relevant code:

- **Rationale belongs in [`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md),
  not in code comments.** A comment may state what a control does; why that approach was
  chosen over another goes in the decision log.
- Do not advance the Python version. See
  [System Requirements](#system-requirements).

## License

**No licence is declared for this project.** There is no `LICENSE` file in this repository
and no licence header in its source, so no licence grant is asserted here — choosing one is
the repository owner's decision. Until an owner adds a `LICENSE` file, treat the code as
all rights reserved and do not assume permission to copy, modify or redistribute it.

## Contact and Ownership

Both channels below are surfaces of this repository, so neither depends on an address
being kept up to date:

- **Questions, bugs and feature requests** — open a GitHub issue on this repository.
- **Suspected vulnerabilities** — **do not report a suspected vulnerability in an
  issue, a pull request, or a discussion.** Those are public, and opening one discloses
  the weakness before a fix exists. Use the repository's **Security** tab and choose
  **Report a vulnerability**, which is private to the maintainers. The full process is in
  [`SECURITY.md`](SECURITY.md).

No email address is published here. An earlier revision carried a placeholder one, and a
placeholder contact is worse than none: a reporter who uses it reaches nobody while
believing they have made contact. A deployment that wants an email channel should add a
mailbox it monitors, to [`SECURITY.md`](SECURITY.md) as well as here, and should test it
before publishing it.
