# Security Policy

This is the security policy for `apartment-finder-service`. It states which lines of the
code exist to receive a fix, what this repository's code does and does not cover, where
its security posture is recorded, and how its verification gates are run.

> [!IMPORTANT]
> **A vulnerability can be reported privately today; the terms around that report cannot
> be relied on yet.** The repository's **Security and quality** tab offers **Report a
> vulnerability**, so the channel exists and works. Two things remain unsettled: nothing
> inside this repository can establish that a filed report is *read*, and no response,
> disclosure, recognition or legal terms have been authorized by the repository owner. See
> [Reporting a Vulnerability](#reporting-a-vulnerability), which keeps the working channel
> and the unsettled terms apart, and [Owner action required](#owner-action-required), which
> lists exactly what the owner must settle. Everything else in this document is a statement
> of fact about the repository and stands on its own.

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
control, rather than resolved by advancing the interpreter. **Eight** advisories are
currently accepted on that basis, and they divide into two sets that should not be read as
one:

| Set | Manifest | Accepted | Packages | In the deployed image |
| --- | --- | --- | --- | --- |
| Runtime | `backend/requirements.txt` | 7 | 3 | Yes |
| Development | `backend/requirements-dev.txt` | 1 | 1 | No |
| **Total** | both | **8** | 4 | |

The seven runtime advisories sit in packages the deployed image installs, so each carries a
control argued against the specific defective code path. The one development advisory sits
in the test framework, which no deployed process installs, so its control is that absence.
Every figure a reader will meet elsewhere in this repository states which of the two it
describes.

A third manifest, `backend/requirements-audit.txt`, declares the dependency-audit
instrument and is **not audited**: `pip-audit` resolves a dependency tree of its own, and
auditing the manifest that declares it reports the scanner's supply chain as this
project's. That accounting is what took the accepted total to fourteen in an earlier
revision; six of the seven identifiers then in the development set belonged to the
instrument rather than to anything this repository tests or ships. They are not suppressed
now — no ignore list names one of them — because the manifest carrying them is no longer
part of the measured surface. *The audit instrument's own tree* in
[`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) records the measurement
and what bounds the instrument's exposure.

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

Each of the eight is recorded in
[`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) with its unreachable
fix version, the measured ceilings that put the fix out of reach, the reachability evidence
for this codebase, and its compensating control. They are not enumerated here, so that the
register remains the one place they are maintained. A report concerning any of them is
welcome — please check the register first, because it may already name the control that
answers it, and it is explicit about the limits of that evidence.

## Reporting a Vulnerability

> [!IMPORTANT]
> **Three things are in three different states here, and this section keeps them apart.**
> The **channel is enabled** — the **Report a vulnerability** button is present on this
> repository's public **Security and quality** tab, so a report can be filed now.
> **Monitoring is unverified** — a report notifies whoever holds maintainer access through
> notification settings held in their own personal accounts, and no file inside this
> repository can establish that one of them reads it. **The terms are unauthorized** — no
> response, disclosure, recognition or legal terms have been settled by the repository
> owner, so until it completes [Owner action required](#owner-action-required) below,
> **treat those terms as incomplete rather than as a commitment**. See
> [Until monitoring is confirmed](#until-monitoring-is-confirmed) for what to do with a
> finding in the meantime.

**Do not open a public issue, pull request, or discussion for a suspected
vulnerability.** Doing so discloses the weakness to everyone before a fix exists.
That instruction stands regardless of the state of this section.

**Channel — GitHub private vulnerability reporting.** Open the repository's **Security and
quality** tab and choose **Report a vulnerability**, which is on the overview the tab opens
on. The same button appears again on the **Advisories** page, reached from the sidebar's
**Reporting** group — a sidebar that is shown once you are on Advisories or Security policy
rather than on the overview itself, so the one-step route above is the shorter one. Filing
creates a draft advisory visible only to the repository's maintainers, notifies them through
their existing GitHub notification settings, and requires no email address from either
side; it does require a GitHub account, because the form asks an unauthenticated visitor to
sign in first and returns them to it afterwards. It is the only channel this policy
publishes.

**What has been observed about it.** On this repository's public **Security and quality**
tab, read while signed out, the **Report a vulnerability** button is present and enabled, on
the overview and again on the Advisories page — so private vulnerability reporting is
enabled here and a report can be filed today. No advisory has been published, and the
Advisories list is empty. The same page also reads *No security policy detected*. That is a
statement about this file, not about the channel: GitHub links a policy only from a
repository's default branch, and this document is not on it yet. The two are independent
surfaces — GitHub's own documentation notes that private vulnerability reporting is separate
from a repository's `SECURITY.md` — and neither of them says anything about whether a filed
report is read.

*Operator prerequisite:* private vulnerability reporting is **off** by default on a GitHub
repository and has to be enabled explicitly — Settings, then **Advanced Security** under the
sidebar's Security section, then *Private vulnerability reporting* — and on this repository
that step is already done, which is what the observation above records. What is not
established is monitoring. A privately reported vulnerability notifies maintainers and
security managers only when they watch the repository for all activity or for security
alerts and have notifications enabled, so whether a report reaches a person depends on
settings held in personal accounts, outside this repository. Confirming that is item 1 of
[Owner action required](#owner-action-required). A reporter can check the channel itself in
one step: if the **Security and quality** tab offers the button, the channel is enabled.

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

The channel above is a repository surface, it is enabled, and it needs no address — but four
further things must be settled by the repository owner, with legal input where the last one
is concerned, before a reporter can rely on more than the channel itself. They are listed
rather than assumed, because a disclosure policy that promises what nobody has agreed to
is worse than one that is visibly unfinished: it misdirects reports and creates
expectations the project may not meet.

| # | What must be decided or configured | Why it cannot be filled in here |
| --- | --- | --- |
| 1 | **Confirmation that a private report is read.** Enablement is done and needs no repeating; what remains is to watch this repository for security alerts with email notification on, file a test report, and observe that it arrives and is answered | Notification delivery turns on settings held in maintainers' personal accounts, and whether a person then reads what arrives is a human arrangement. Neither can be asserted from a file inside the repository |
| 2 | **Response targets**, if any are to be offered — acknowledgement, assessment and update intervals | A target is a commitment by whoever is on the other end of the channel. No maintainer rota or on-call arrangement exists here to make one against |
| 3 | **Disclosure and recognition terms** — any coordinated-disclosure window the project asks reporters to observe, and whether credit is offered | Both bind the project's future conduct, and one of them binds a reporter's |
| 4 | **Safe-harbour terms, and whether a bug-bounty programme exists.** `documentation/Technical Specifications.md` records a bug bounty as an intended part of this project's vulnerability-management protocol; **no such programme is in operation today**, and whether one is established, and on what terms, is the owner's decision | Safe harbour is a legal undertaking not to pursue good-faith research, and a bounty is a financial commitment. Neither can be published on a project's behalf without its authorization |

Until item 1 is confirmed, this repository can demonstrate that a private report will be
**received** but not that it will be **read**. That is a narrower gap than an absent
channel, and it is still a gap in the project's security posture, so it is stated here
rather than papered over with a placeholder address.

### Until monitoring is confirmed

If you have found something while item 1 above is still outstanding, please:

- **Do not** post details publicly, and do not include a working exploit anywhere
  public.
- **File the report through the Security and quality tab.** The channel is enabled and the
  report is private, so filing it is the right first step rather than a fallback.
- If nothing acknowledges it, contact the repository owner through whatever private channel
  their profile or organization publishes, and ask them to confirm that advisory
  notifications reach them.
- Keep the details until you hear back. A finding held quietly for a week is far better
  than one disclosed publicly today.

### What to include

A report is easiest to act on when it carries:

- The affected component or file path, and the branch or commit you observed it on.
- The impact — what an attacker gains, in terms of confidentiality, integrity, or availability.
- Reproduction steps, or a proof-of-concept, sufficient to confirm the finding.
- Any suggested remediation. Welcome, but never required.

### What to expect

**No response times are committed, because nobody is yet accountable for reading what the
channel receives.** A commitment to acknowledge a report within a number of days needs two
conditions: something that receives the report, and someone answerable for reading it. The
first holds — the channel is enabled. **Item 1 above is what establishes the second**:
watching this repository for security alerts is what carries a report to a person, and
observing that a test report was answered is what makes someone accountable for it. Until
that is confirmed, publishing a schedule here would be a promise this repository cannot
keep. Item 2 is what would set the targets themselves.

The targets below are therefore a **proposal, not a commitment**. They take effect only when
an operator turns them on — that is, once monitoring is confirmed and this paragraph is
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

**A note on the frontend, because it affects how you read this policy's scope.** Frontend
integration is **currently non-operational and separately scoped**: the client in
`frontend/` cannot presently consume this API. The defects predate this policy and are not
security weaknesses in the service: the client calls a different authentication route and
reads a response field the backend does not return, omits the `Authorization` header on
protected calls, and integrates PayPal through a different product contract. Repairing it
requires an authorized change to `frontend/`, which is out of scope here — and the backend
will not be weakened to accommodate it.

**Its continuous-integration job does gate, and it passes.** `.github/workflows/ci.yml`
runs a `Frontend gates` job with no `continue-on-error`: a linter with a warning budget
recording the count the read-only source already carries, and the test command with
`--passWithNoTests` because the workspace holds no test file. It is a **limited** gate — it
runs no `tsc --noEmit` and no production build, so a green result does not prove the client
compiles — but it is not a tolerated failure, and a red one blocks the change like any other.
The paragraph headed *On the tolerated job*, further down this policy, states this once more
with the history behind it.

### Safe harbour — proposed, not yet in force

**No safe-harbour undertaking is in force.** Item 4 of *Owner action required* above is
where that is settled: safe harbour is a legal commitment not to pursue good-faith
research, and it cannot be published on the project's behalf without its authorization.
What follows is therefore the scope such an undertaking would be proposed against, in the
same form as the response targets above — a proposal an operator turns on by replacing this
paragraph with a statement that it is in force.

The limits below are also **statements of scope that hold today**, independently of any
undertaking: they say where a finding belongs and what this codebase does deliberately, so
a reporter can tell a defect from a documented decision.

- **Third-party services.** PayPal, Zillow, SendGrid and Google Cloud are separate products with their own disclosure processes. A defect in one of them is theirs to fix; report it to them directly.
- **`frontend/` source.** It is in this repository, but the change set that produced this policy treated it as read-only reference material, so a finding there is **recorded rather than patched** under the current scope. That is a statement of the authorized change scope, not a judgement that frontend findings are unimportant — and it is a boundary the owner can lift.
- **Findings requiring an already-compromised host, or local filesystem access to the machine running the service.** Whether these are accepted is part of item 4's decision, since it is the scope any safe-harbour undertaking would be made against; they are noted here because the codebase assumes the host is trusted.
- **Volumetric denial of service.** Traffic floods and volume-driven resource exhaustion are a deployment and edge-infrastructure concern rather than a property of this code. The application-level resource controls it does carry — a bounded page size, a request-body cap and rate limits on the credential endpoints — are in scope as code.
- **Two email addresses sharing a login-throttle row.** A refused login updates one row of a fixed-size table, selected by a keyed digest of the submitted address, so two different addresses can select the same row and briefly serialise behind one another's write. That is intended rather than a defect: it is what lets every refusal branch perform the same database work, which is what removes the timing difference between an account that exists and one that does not. The row holds no address, no credential and no account identifier, only a count and a timestamp, and the set of rows never grows. The reasoning and the accepted trade-off are recorded at row 94.7.1 of [`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md).

## Security Posture and Where It Is Documented

| Document | What it holds |
| --- | --- |
| [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) | Two registers covering all eight accepted advisories &mdash; seven runtime and one development-only &mdash; with their unreachable fix versions, the measured Python 3.9 ceilings, the reachability evidence with its stated assumptions, each named compensating control, and the total-suppression accounting. |
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
# Lint
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

# Dependency audit — the development manifest, suppressed separately.
# backend/requirements-audit.txt declares the instrument and is not audited.
pip-audit --strict -r backend/requirements-dev.txt \
  --ignore-vuln PYSEC-2026-1845

# Static analysis
bandit -r backend/app -ll

# Guard 1 — the omitted package must stay omitted
! pip show python-multipart

# Guard 2, layer 1 — the accepted advisories must stay textually unreachable
! grep -rEn "request\.form|request\.url|StaticFiles|HTTPEndpoint|Route\(|set_key|unset_key|\bclick\b" \
    --include=*.py backend/app/

# Guard 2, layer 2 — the same question resolved semantically. Not a workflow
# step of its own: this module runs inside the security suite below, and is
# named here because it is the layer that answers the question semantically.
python -m pytest backend/tests/security/test_residual_risk_guards.py -q

# Security suite, which the workflow runs first so coverage starts here
python -m pytest backend/tests/security -q \
  --cov=backend/app \
  --cov-report= \
  --cov-fail-under=0

# Everything else, appending to that coverage
python -m pytest backend/tests \
  --ignore=backend/tests/security \
  --cov=backend/app \
  --cov-append \
  --cov-report=xml:backend/coverage.xml
```

| Gate | Expected outcome |
| --- | --- |
| Lint | Clean. Run from `backend/` because that is what the workflow does; the configuration comes from the single `setup.cfg` at the repository root, which `flake8` finds by searching upwards. On Windows add `--jobs=1`: the default parallel mode exhausts the interpreter's 64-handle wait limit and aborts before reporting anything. The workflow runs on Linux, where the default is correct. |
| Dependency audit — runtime | Exits zero. The seven suppressed identifiers are the residual advisories; anything else is a new finding, and `--strict` makes an unaudited package a failure rather than a warning. |
| Dependency audit — development | Exits zero. Its **one** identifier is a **different** set, documented in the *Development register* of [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md). Eight identifiers are suppressed across the two manifests: seven against the runtime manifest and one against this one. |
| Static analysis | No findings at Medium severity or above. |
| Guard 1 — omitted package | `pip show` fails, because the package is deliberately absent from the manifest. |
| Guard 2, layer 1 — textual reachability | No match, so no accepted residual advisory has become textually reachable in `backend/app/`. |
| Guard 2, layer 2 — semantic reachability | Passes. It walks the application's import graph and syntax trees, so a construct reintroduced under another name is still found. |
| Security suite | Passes, including the forty-five-cell role matrix — nine routes against five principals, anonymous included. |
| Everything else, with coverage | Passes. Together with the security suite this is the gate the deployment workflow waits on, and the two partitions are what accumulate one coverage report. |

Continuous integration runs more than the nine gates above. It additionally checks the
secret and ignore policy, applies every Alembic revision against a PostgreSQL 13 service,
reverses the chain one revision at a time and re-applies it, asserts that exactly one
account holds the administrative role, imports the application entrypoint, runs the cases
marked `postgres` against that service, and probes a live process on `/health`,
`/health/ready`, `GET /listings/` and a full registration and sign-in round trip. The nine
gates above are listed on their own, one per row of the table, because they are the ones a
reporter can run without a PostgreSQL service.

Four details in the block are load-bearing rather than incidental, and dropping any of
them produces a different answer:

- **`-r <manifest>` is mandatory.** A bare invocation audits the whole active environment
  and folds the audit tool's own dependency tree into the report, which inflates the count
  and obscures which findings belong to this application.
- **`--strict` and the `--ignore-vuln` flags are not decoration.** Without `--strict`,
  `pip-audit` treats a package it cannot resolve as a warning and still exits zero, so a
  manifest entry that no longer audits would pass silently. Without the `--ignore-vuln`
  flags the audit exits **non-zero**, because the accepted advisories are still reported: a
  plain `pip-audit -r backend/requirements.txt` is a **diagnostic** command rather than the
  gate. If the plain form fails, compare its output against
  [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) before treating the
  failure as a regression.
- **The two audited manifests carry different suppression lists**, eight identifiers in
  total. Each set has its own section in
  [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) &mdash; the *Runtime
  register* for the seven the deployed image installs, the *Development register* for the
  single test-framework advisory that never ships &mdash; and the two sets are disjoint.
  Applying one list to the other manifest fails. A third manifest,
  `backend/requirements-audit.txt`, declares the audit instrument and is installed but
  audited by neither step.
- **The two guards are narrower than they look.** They are the executable part of the
  compensating controls for the accepted advisories, and between them they assert exactly
  two facts: one named package is absent, and eight named patterns do not appear in Python
  files under **`backend/app/`**. That scope is the guard's own, and it is the code whose
  reachability the acceptances are argued from. Measured on this tree, those patterns match
  nothing under `backend/app/` and their only matches anywhere under `backend/` are the
  literals inside `backend/tests/security/test_residual_risk_guards.py`, which is the
  module that names them in order to assert their absence. The guards do not check the
  runtime platform, the six further patterns in the register's reachability measurement, or
  any code outside `backend/app/`. Their leading `!` inverts the exit status, because for
  both the desired result &mdash; the package is absent, the pattern does not match &mdash;
  is what makes the underlying command exit non-zero.

[`README.md`](README.md) lists the full local and release verification set, which is
**wider** than the nine commands above: it adds `terraform fmt -check` and
`terraform validate`, the Alembic round trip against a disposable database, the
application-import gate and the manifest checks. Each of those does run in continuous
integration, in the `infrastructure`, `backend`, `runtime-integration` or `integration`
job, and the readme's *Enforced by* column names which. Four entries in that set run
nowhere but locally: `bash -n` over the two release scripts, the client-side
`kubectl create --dry-run` schema check, opening the executive presentation in a browser,
and the credential-rotation runbook.

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
invoked directly over the whole of `frontend/src`, its report is judged by
`.github/scripts/check_frontend_lint_budget.js` against the count the workflow declares in
`ESLINT_WARNING_BUDGET`, and the one unparseable file's finding is exempted from that
budget rather than hidden from the lint, so it stays visible in
the uploaded report and is recorded as a reported finding, and the suite runs with
`--passWithNoTests` because the workspace carries no test file. It is a **limited** gate:
it runs no `tsc --noEmit` and no production build, so a green result does not prove the
client compiles. There is therefore no job whose red build a reader should discount, and
no green one a reader should over-read.

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

- **Three items closed by a change of state rather than by a decision.**
  `frontend/package-lock.json` is now tracked, so the reported absence of a frontend
  dependency lock file is no longer true of this tree. The Kubernetes objects and the secret
  delivery into the running pod are now declared here, at `infrastructure/kubernetes/`, and
  applied through `scripts/render_kubernetes_manifests.sh` by both release paths; an earlier
  revision of this policy said they were performed outside this repository. And the frontend
  job now passes and gates rather than being tolerated. Nothing was decided in any of the
  three; the tree changed.
- **Two items are owned by an operator rather than by code.** The declared cluster objects
  must **exist** before the first release, and nothing here can reach a cluster to create
  them; and the deployment job needs a self-hosted runner with a network path to the private
  control plane. Both are stated in full at
  [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) O-7, with the operator
  contract in the README's Deployment section.

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
