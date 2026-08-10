# Security Policy

This is the security policy for `apartment-finder-service`. It states which lines of the
code exist to receive a fix, what this repository's code does and does not cover, where
its security posture is recorded, and how its verification gates are run.

> [!IMPORTANT]
> **The vulnerability-reporting process is not yet operational.** No monitored private
> channel has been configured and no response, disclosure, recognition or legal terms
> have been authorized by the repository owner. See
> [Reporting a Vulnerability](#reporting-a-vulnerability), which lists exactly what the
> owner must settle. Everything else in this document is a statement of fact about the
> repository and stands on its own.

This document states policy and fact only. Where a reader would ask *why* a control was
built a particular way, or *why* an advisory was accepted rather than fixed, the answer is
a link to [`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md), which is this
repository's single source of truth for that question.

## Supported Versions

**This is a description of the repository's branch structure, not a support
commitment** — no maintenance or back-port commitment has been authorized, which is item
2 of [Owner action required](#owner-action-required).

There is one line of code to fix, and it is `main`. The repository maintains no release
branches and publishes no tagged releases, so there is no older line a fix could be
back-ported to.

| Version / Branch | State |
| --- | --- |
| `main` (current) | The only line. Any fix lands here |
| Release branches | None exist |
| Tagged releases | None published |

### Runtime baseline

The service targets **Python 3.9**, and that is a deliberate, hard pin rather than a
default left to drift. The pin is load-bearing in **five** places, and all five must
agree:

| # | Pin site | What pins it | Kind |
| --- | --- | --- | --- |
| 1 | `infrastructure/docker/Dockerfile.backend` | `FROM python:3.9-slim` | Version declaration |
| 2 | `.github/workflows/ci.yml` | `python-version: '3.9'` | Version declaration |
| 3 | `infrastructure/terraform/main.tf` | `runtime = "python39"` | Version declaration |
| 4 | `scripts/deploy.sh` | `--runtime python39` | Version declaration |
| 5 | `backend/app/tasks/listing_updater.py` | `@asyncio.coroutine` | **Language construct** |

The fifth site differs in kind from the other four and is the reason the pin is
self-enforcing rather than merely configured: `@asyncio.coroutine` was removed in
CPython 3.11, so the application code would itself stop working on a newer interpreter.
Counting only the version declarations understates the constraint. The single maintained
inventory of these sites, with the line numbers each was verified at, is
[`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) under *The runtime
pin*; this table restates it and must not diverge from it.

Two consequences matter to a reporter or an auditor.

**Dependency advisories.** Where a dependency's only available fix requires Python 3.10 or
later, the advisory is accepted as documented residual risk with a named compensating
control, rather than resolved by advancing the interpreter. **Fourteen** advisories are
currently accepted on that basis, and they divide into two sets that should not be read as
one:

| Set | Manifest | Accepted | Packages | In the deployed image |
| --- | --- | --- | --- | --- |
| Runtime | `backend/requirements.txt` | 7 | 3 | Yes |
| Development | `backend/requirements-dev.txt` | 7 | 5 | No |
| **Total** | both | **14** | 8 | |

The seven runtime advisories sit in packages the deployed image installs, so each carries a
control argued against the specific defective code path. The seven development advisories
sit in test, lint and audit tooling that no deployed process installs, so their control is
that absence. Every figure a reader will meet elsewhere in this repository states which of
the two it describes.

**Hosting platform.** The provider retired the Python 3.9 runtime of its managed serverless
functions product on **5 April 2026**, so that hosting option is closed at this version.
Sites 3 and 4 above therefore declare a runtime the provider now refuses, and both are held
behind an explicit authorization gate that defaults to off &mdash;
`var.cloud_function_deployment_authorized` in the configuration and
`CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED` in the deployment script &mdash; so no release
attempts a create that cannot succeed, and the periodic ingestion workload runs instead as a
Kubernetes CronJob on the pinned backend image. This is not a vulnerability in the service
and carries no exposure for it, but it is a current operational constraint an auditor
assessing deployment readiness needs, and it is registered as accepted residual risk
alongside the advisories above.

Each of the fourteen is recorded in
[`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) with its unreachable
fix version, the measured ceilings that put the fix out of reach, the reachability evidence
for this codebase, and its compensating control. They are not enumerated here, so that the
register remains the one place they are maintained. A report concerning any of them is
welcome — please check the register first, because it may already name the control that
answers it, and it is explicit about the limits of that evidence.

## Reporting a Vulnerability

> [!IMPORTANT]
> **This section is not yet operational. No monitored private channel is operational yet.**
> No monitored private reporting channel has been configured for this repository, and no response, disclosure, recognition or
> legal terms have been authorized by the repository owner. Until the owner completes
> [Owner action required](#owner-action-required) below, **treat this section as
> incomplete rather than as a commitment**, and see
> [If no channel is configured yet](#if-no-channel-is-configured-yet) for what to do
> in the meantime.

**Do not open a public issue, pull request, or discussion for a suspected
vulnerability.** Doing so discloses the weakness to everyone before a fix exists.
That instruction stands regardless of the state of this section.

**Channel — GitHub private vulnerability reporting.** Open the repository's **Security**
tab and choose **Report a vulnerability**. This creates a draft advisory visible only to
the repository's maintainers, notifies them through their existing GitHub notification
settings, and requires no email address from either side. It is the only channel this
policy publishes, and it is monitored by whoever holds maintainer access to the
repository.

*Operator prerequisite:* private vulnerability reporting is **off** by default on a
GitHub repository and must be enabled explicitly, under Settings → Code security and
analysis → Private vulnerability reporting. Until it is enabled the **Report a
vulnerability** button does not appear and this channel does not exist. A reporter can
check in one step: if the Security tab offers no such button, the channel is not
enabled. It is the repository owner's responsibility to ensure the channel is
monitored.

**On email.** This policy deliberately publishes **no email address.** An earlier revision
carried a placeholder one, which is worse than publishing none: a reporter who uses it
reaches nobody, and believes a disclosure has been made. A deployment that needs an email
channel should add a mailbox it actually monitors here — a role address such as
`security@` its own domain, never a personal one — and should not add an address it has
not first tested end to end. The address that
previously stood in this position, and the matching one in [`README.md`](README.md), were
both an unmodified example-domain placeholder — a value that accepts no mail and monitors
nothing. **No address is published here**, because publishing a placeholder as a
security contact is worse than publishing nothing: it invites a report into a mailbox that
does not exist.

*Operator prerequisite:* provision a mailbox that a person or an alias group actually
reads, then record it in this section and in the README contact block. A mailbox is only a
security contact once someone is accountable for reading it.

### Owner action required

The channel above is a repository surface and needs no address, but three further things
must be settled by the repository owner — with legal input where the last one is
concerned — before a reporter can rely on more than the channel itself. They are listed
rather than assumed, because a disclosure policy that promises what nobody has agreed to
is worse than one that is visibly unfinished: it misdirects reports and creates
expectations the project may not meet.

| # | What must be decided or configured | Why it cannot be filled in here |
| --- | --- | --- |
| 1 | **Verification that the private channel is monitored** — confirm private vulnerability reporting is enabled under **Settings → Code security**, then send a test report and observe that it is received | Whether private reporting is enabled, and whether anyone reads it, are repository settings and human arrangements that cannot be asserted from a file inside the repository |
| 2 | **Response targets**, if any are to be offered — acknowledgement, assessment and update intervals | A target is a commitment by whoever is on the other end of the channel. No maintainer rota or on-call arrangement exists here to make one against |
| 3 | **Disclosure and recognition terms** — any coordinated-disclosure window the project asks reporters to observe, and whether credit is offered | Both bind the project's future conduct, and one of them binds a reporter's |
| 4 | **Safe-harbour terms, and whether a bug-bounty programme exists.** `documentation/Technical Specifications.md` records a bug bounty as an intended part of this project's vulnerability-management protocol; **no such programme is in operation today**, and whether one is established, and on what terms, is the owner's decision | Safe harbour is a legal undertaking not to pursue good-faith research, and a bounty is a financial commitment. Neither can be published on a project's behalf without its authorization |

Until item 1 is confirmed, this repository cannot demonstrate that a private report will
be **read**. That is a gap in the project's security posture, and it is stated here rather
than papered over with a placeholder address.

### If no channel is configured yet

If you have found something and item 1 above is still outstanding, please:

- **Do not** post details publicly, and do not include a working exploit anywhere
  public.
- File the report through the **Security** tab anyway — it is private — and, if you can,
  contact the repository owner through whatever private channel their profile or
  organization publishes, asking them to confirm private vulnerability reporting is on.
- Keep the details until the channel is confirmed. A finding held quietly for a week
  is far better than one disclosed publicly today.

### What to include

Whenever a channel does exist, a report is easiest to act on when it carries:

- The affected component or file path, and the branch or commit you observed it on.
- The impact — what an attacker gains, in terms of confidentiality, integrity, or availability.
- Reproduction steps, or a proof-of-concept, sufficient to confirm the finding.
- Any suggested remediation. Welcome, but never required.

### What to expect

**No response times are committed, because no channel is monitored yet.** A commitment to
acknowledge a report within a number of days is only meaningful if something receives the
report and someone is accountable for reading it. Neither condition holds until an operator
completes one of the two prerequisites above, so publishing a schedule here would be a
promise this repository cannot keep.

The targets below are therefore a **proposal, not a commitment**. They take effect only when
an operator turns them on — that is, once a channel is operational and this paragraph is
replaced by a statement that it is.

| Stage | Proposed target, not yet in force |
| --- | --- |
| Acknowledgement that the report arrived | Within 5 business days |
| Initial assessment — in scope or not, plus a working severity | Within 10 business days |
| Status update while the report remains open | At least every 14 calendar days |

No fix-by date would be promised even then, because the remediation effort cannot be known
before the assessment. The assessment would state what is planned; the status updates would
state where it stands.

### Disclosure

What can be stated without anyone's authorization, because it is a fact about the
repository rather than a promise about conduct, is where this project's security
posture is written down: every accepted risk, every non-trivial decision and the
mapping from finding to fix to test are committed to this repository and listed under
[Security Posture and Where It Is Documented](#security-posture-and-where-it-is-documented).

## Scope

This section describes **what this repository's code covers and what it does not**.
It is a description of the codebase, not a support commitment; the owner has
authorized no support policy, which is item 2 of
[Owner action required](#owner-action-required).

Covered by this repository, and therefore fixable here:

- `backend/` — the API service, including its authentication, authorization, payment, and data-access code.
- `infrastructure/` — the container, Compose, and Terraform definitions.
- `scripts/` — the deployment and developer-setup automation.
- `.github/` — the continuous-integration and continuous-deployment workflows.

Out of scope:

- Findings that require an already-compromised host, or local filesystem access to the machine running the service.
- Volumetric denial of service — traffic floods and resource exhaustion driven by volume alone.
- The third-party services this system integrates with. Report issues in PayPal, Zillow, SendGrid, or Google Cloud to those providers directly.
- `frontend/` source, which the current change set treats as read-only reference material. A finding there cannot be fixed under this scope; it will be recorded rather than patched.

**A note on the frontend, because it affects how you read a red build.** Frontend integration
is **currently non-operational and separately scoped**: the client in `frontend/` cannot
presently consume this API, and its continuous-integration job is expected to fail. The defects predate this policy and are not security weaknesses in
the service: the client calls a different authentication route and reads a response field the
backend does not return, omits the `Authorization` header on protected calls, and integrates
PayPal through a different product contract. Repairing it requires an authorized change to
`frontend/`, which is out of scope here — and the backend will not be weakened to accommodate
it. Treat the frontend job's failure as a known, tracked limitation rather than as a signal
about the security gates, which run in a separate job that it cannot block.

### Safe harbour

Good-faith research that stays within the limits below will not be pursued by this
project:

- **Third-party services.** PayPal, Zillow, SendGrid and Google Cloud are separate products with their own disclosure processes. A defect in one of them is theirs to fix; report it to them directly.
- **`frontend/` source.** It is in this repository, but the change set that produced this policy treated it as read-only reference material, so a finding there is **recorded rather than patched** under the current scope. That is a statement of the authorized change scope, not a judgement that frontend findings are unimportant — and it is a boundary the owner can lift.
- **Findings requiring an already-compromised host, or local filesystem access to the machine running the service.** Whether these are accepted is item 2's decision; they are noted here because the codebase assumes the host is trusted.
- **Volumetric denial of service.** Traffic floods and volume-driven resource exhaustion are a deployment and edge-infrastructure concern rather than a property of this code. The application-level resource controls it does carry — a bounded page size, a request-body cap and rate limits on the credential endpoints — are in scope as code.

## Security Posture and Where It Is Documented

| Document | What it holds |
| --- | --- |
| [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) | Two registers covering all fourteen accepted advisories &mdash; seven runtime and seven development-only &mdash; with their unreachable fix versions, the measured Python 3.9 ceilings, the reachability evidence with its stated assumptions, each named compensating control, and the total-suppression accounting. |
| [`docs/security/CREDENTIAL_ROTATION.md`](docs/security/CREDENTIAL_ROTATION.md) | The staged runbook: provision the new configuration, deploy and verify, then revoke and rotate the credentials exposed through version control. |
| [`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md) | Every non-trivial security decision, the alternatives that existed, and the risk each carries. |
| [`docs/security/TRACEABILITY_MATRIX.md`](docs/security/TRACEABILITY_MATRIX.md) | The bidirectional mapping from finding, to the file that fixes it, to the test that verifies it. |
| [`docs/review/CRITICAL_DECISIONS.md`](docs/review/CRITICAL_DECISIONS.md) | The five highest-risk decisions, each with its reviewer persona and that reviewer's checks. |
| [`.env.example`](.env.example) | The complete configuration contract. |
| [`README.md`](README.md) | Setup, and the full verification command set. |

`.env.example` is a committed template that holds no secret — every secret-bearing value
in it is a non-functional placeholder. Configuration is validated at startup rather than
at first use, so the application refuses to start on a weak or placeholder signing key, on
a JWT algorithm outside the `HS256`/`HS384`/`HS512` allowlist, or on a production
environment paired with sandbox payment credentials.

### Previously exposed credentials

**Credentials this repository previously exposed must be treated as compromised.**
Removal stops future exposure; only revocation and rotation address exposure that has
already happened.

Four credentials were exposed, by two different routes:

| Credential | Exposure route | Where the disclosure lives |
| --- | --- | --- |
| Database connection string | Committed as a literal in `infrastructure/docker/docker-compose.yml` | Repository history, and every clone, fork, mirror and backup of it |
| Google Cloud service-account key | Named as a mounted credential path by the same file | Repository history, plus any host that held the key file |
| JWT signing key | The placeholder `scripts/setup_dev_environment.sh` wrote into every developer environment | Repository history — and the value is public knowledge, so every deployment that used it had a publicly known signing key |
| Listing-provider (Zillow) API key | Never committed. `backend/app/services/zillow_service.py` put it in the request query string and printed exception text carrying that URL | Log archives, log-aggregation indexes, proxy access logs and the provider's own access logs |

The distinction matters operationally: a history rewrite addresses the first three
and does nothing for the fourth, whose disclosure sits in logs rather than in git.
All four have been removed from the working tree and from the code paths that leaked
them — the provider key now travels in a request header and every failure is emitted
through a redacting structured logger — and a root `.gitignore` and `.dockerignore`
now prevent reintroduction.

A fifth secret, the PayPal webhook identifier, was never exposed but is new
configuration an operator must provision. It is covered by the same runbook.

If you operate a deployment built from this repository, follow
[`docs/security/CREDENTIAL_ROTATION.md`](docs/security/CREDENTIAL_ROTATION.md). Rotation
of an exposed credential is its Stage C, and within that stage the sequence is revoke,
then rotate, then delete from history, then review prior access — the order is
load-bearing, and rotation cannot be rolled back. **Its Stage A runs before the
deployment**, because the hardened code will not start until the configuration it requires
is in place; do not read "rotation is last" as deferring that.

## Verification Gates

The following gates run in continuous integration on every push and every pull request to
`main`, so a regression is caught rather than discovered. Anyone assessing a report can
run the same commands locally, and they are reproduced here **exactly as
`.github/workflows/ci.yml` invokes them** — including the flags. An earlier revision of
this section paraphrased them: it omitted `--strict`, omitted every `--ignore-vuln`
identifier, omitted the lint and full-suite gates, and ran `pip-audit` from the repository
root. Each of those differences changes the result, so a reader who followed the old
block did not reproduce the gate they thought they were reproducing.

```bash
# Lint — the workflow runs this from backend/; `flake8 backend` from the
# repository root is equivalent, and setup.cfg carries both path forms so that
# either invocation directory resolves the frozen-module exception.
cd backend
flake8 .
cd ..

# Dependency audit — the runtime manifest, with its seven accepted advisories suppressed
pip-audit --strict -r backend/requirements.txt \
  --ignore-vuln PYSEC-2026-161 \
  --ignore-vuln PYSEC-2026-248 \
  --ignore-vuln PYSEC-2026-249 \
  --ignore-vuln PYSEC-2026-2280 \
  --ignore-vuln PYSEC-2026-2281 \
  --ignore-vuln PYSEC-2026-2270 \
  --ignore-vuln PYSEC-2026-2132

# Dependency audit — the development manifest, suppressed separately
pip-audit --strict -r backend/requirements-dev.txt \
  --ignore-vuln PYSEC-2026-1845 \
  --ignore-vuln PYSEC-2026-3625 \
  --ignore-vuln PYSEC-2026-1374 \
  --ignore-vuln PYSEC-2026-1375 \
  --ignore-vuln PYSEC-2026-2275 \
  --ignore-vuln PYSEC-2026-141 \
  --ignore-vuln PYSEC-2026-142

# Static analysis
bandit -r backend/app -ll

# Guard 1 — the omitted package must stay omitted
! pip show python-multipart

# Guard 2, layer 1 — the accepted advisories must stay textually unreachable
! grep -rEn "request\.form|request\.url|StaticFiles|HTTPEndpoint|Route\(|set_key|unset_key|\bclick\b" \
    --include=*.py backend/app/

# Guard 2, layer 2 — the same question resolved semantically
python -m pytest backend/tests/security/test_residual_risk_guards.py -q

# Full backend suite, with coverage
python -m pytest backend/tests --cov=backend/app --cov-report=xml:backend/coverage.xml

# Security suite
python -m pytest backend/tests/security -q
```

| Gate | Expected outcome |
| --- | --- |
| Lint | Clean. Run from `backend/` because that is what the workflow does; the configuration comes from the single `setup.cfg` at the repository root, which `flake8` finds by searching upwards. |
| Dependency audit — runtime | Exits zero. The seven suppressed identifiers are the residual advisories; anything else is a new finding, and `--strict` makes an unaudited package a failure rather than a warning. |
| Dependency audit — development | Exits zero. Its seven identifiers are a **different** set, documented in the development manifest itself rather than in the residual-risk register. |
| Static analysis | No findings at Medium severity or above. |
| Guard 1 — omitted package | `pip show` fails, because the package is deliberately absent from the manifest. |
| Guard 2 — advisory reachability | No match, so no accepted residual advisory has become reachable. |
| Full suite | Passes. This is the gate the deployment workflow waits on. |
| Security suite | Passes, including the forty-five-cell role matrix — nine routes against five principals, anonymous included. |

Three details in the block above are load-bearing rather than incidental, and dropping any
of them produces a different answer:
Continuous integration runs more than the five commands above. It additionally applies both
Alembic revisions against a PostgreSQL 13 service, reverses and re-applies them, asserts that
exactly one account holds the administrative role, imports the application entrypoint, runs
the whole test suite, and probes a live process on `/health`, `/health/ready`,
`GET /listings/` and a full registration and sign-in round trip. The five commands above are
listed on their own because they are the ones a reporter can run without a database.

The `-r backend/requirements.txt` argument to `pip-audit` is mandatory. A bare invocation
audits the whole environment and folds the audit tool's own dependency tree into the
report, which inflates the count and obscures which findings belong to this application.

- **`-r <manifest>` is mandatory.** A bare invocation audits the whole environment and
  folds the audit tool's own dependency tree into the report, which inflates the count and
  obscures which findings belong to this application.
- **`--strict` is mandatory.** Without it `pip-audit` treats a package it cannot resolve
  as a warning and still exits zero, so a manifest entry that no longer audits would pass
  silently.
- **The two manifests carry different suppression lists**, fourteen identifiers in total.
  Only the runtime seven are the subject of
  [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md); the development seven
  never ship and are documented where they are declared. Applying one list to the other
  manifest fails.

- **`--strict` and the `--ignore-vuln` flags are not decoration.** Without them the audit
  exits **non-zero**, because the seven accepted advisories are still reported. A plain
  `pip-audit -r backend/requirements.txt` is therefore a **diagnostic** command — useful
  for seeing the current findings, and **not** equivalent to the gate. If you run the
  plain form and it fails, compare its output against
  [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) before treating the
  failure as a regression.
- **The `-r <manifest>` argument is mandatory in either form.** A bare invocation audits
  the whole active environment and folds the audit tool's own dependency tree into the
  report, which inflates the count and obscures which findings belong to this application.
- **The last two gates are narrower than they look.** They are the executable part of the
  compensating controls for the accepted advisories, and between them they assert exactly
  two facts: one named package is absent, and eight named patterns do not appear in Python
  files under `backend/`. They do not check the runtime platform, the six further patterns
  in the register's reachability measurement, or anything outside `backend/`. Their leading
  `!` inverts the exit status, because for both the desired result — the package is absent,
  the pattern does not match — is what makes the underlying command exit non-zero.

The pipeline additionally runs the full backend suite with coverage, `flake8` from the
`backend/` directory and the frontend lint and test jobs.
[`README.md`](README.md) lists the full local and release verification set, which is
**wider** than this pipeline subset — it includes the application-import gate,
`terraform validate` and the Alembic round trip, none of which run in continuous
integration.

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

## Payment Data

The PayPal integration uses a hosted redirect: the payer completes payment on PayPal's own
pages, and this service handles only plan identifiers, order identifiers, and
signature-verified webhook notifications. **No card number enters or is stored by this
service.**

That is a factual statement about the data this service handles. It is not an attestation
of conformance to any compliance framework, and no such conformance is claimed anywhere in
this repository. Any future proposal that moves card entry into this service should be
treated as a material change to this property.

## Reported but Unresolved Findings

Not every issue identified during security review has been fixed. Some fell outside the
authorized change scope — several of them in `frontend/` source, which was read-only for
that work — and others need an operator action this repository cannot perform. All are
**reported and awaiting confirmation or an operator action, not resolved**.

They are published as an itemised inventory rather than as a count, in
[`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md) at §35.1. That section is
the single place the inventory lives and the one to read: it names each item, says why it is
still open, and separates the items awaiting a decision from the items awaiting an operator.
Two properties of it are worth knowing in advance.

- **One item closed by a change of state rather than by a decision.**
  `frontend/package-lock.json` is now tracked, so the reported absence of a frontend
  dependency lock file is no longer true of this tree. Nothing was decided and nothing was
  fixed.
- **Four items are owned by an operator rather than by code.** This repository defines no
  Kubernetes manifests; secret *delivery* into the running pod is authorized here but
  performed outside this repository; the deployment job needs a runner with a network path to
  the private control plane; and the frontend is not shippable, so its continuous-integration
  job is a tolerated failure that gates nothing.

This policy quotes no total. An earlier revision published one, it drifted from the inventory
it summarised, and §35.1 records that drift as the reason a count is no longer published in
two places.

Two items are worth naming here rather than only by reference, because they bear directly
on how this policy should be read:

- **The `@asyncio.coroutine` construct** in `backend/app/tasks/listing_updater.py` is
  forward-compatibility debt, not a vulnerability. It is valid on the pinned interpreter,
  it is verified as callable there, and it will fail on Python 3.11 or later. It is
  retained deliberately, and it is the reason the pin is a property of the code — see
  [Runtime baseline](#runtime-baseline). If the pin is ever lifted, this is the item to
  discharge first.
- **Token revocation is not implemented.** A unique identifier is minted in every access
  token, so revocation becomes implementable without a schema change, but no revocation
  mechanism exists today. A token remains valid until it expires. Report anything that
  depends on revoking a token as an issue against that gap rather than as a bypass.

Please do not read this policy as a claim that the repository is free of known issues. It
is a claim that the known issues are written down, that each carries a stated disposition
checked against the tree rather than assumed, and that the gates above keep the resolved
ones from regressing.
