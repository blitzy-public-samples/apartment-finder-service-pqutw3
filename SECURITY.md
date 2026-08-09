# Security Policy

This is the vulnerability disclosure policy for `apartment-finder-service`. It states
which versions receive security fixes, how to report a suspected vulnerability privately,
what is in scope, and where this repository's security posture is recorded.

This document states policy only. Where a reader would ask *why* a control was built a
particular way, or *why* an advisory was accepted rather than fixed, the answer is a link
to [`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md), which is this
repository's single source of truth for that question.

## Supported Versions

Security fixes are applied to the current `main` branch only. This repository maintains
no release branches and publishes no tagged releases, so there is no older line to
back-port a fix to.

| Version / Branch | Supported |
| --- | --- |
| `main` (current) | Yes — security fixes land here |
| Release branches | None exist |
| Tagged releases | None published |

### Runtime baseline

The service targets **Python 3.9**, and that is a deliberate, hard pin rather than a
default left to drift. The pin is load-bearing in four places, and all four must agree:

| Pin site | Value |
| --- | --- |
| `infrastructure/docker/Dockerfile.backend` | `FROM python:3.9-slim` |
| `.github/workflows/ci.yml` | `python-version: '3.9'` |
| `infrastructure/terraform/main.tf` | `runtime = "python39"` |
| `scripts/deploy.sh` | `--runtime python39` |

One consequence matters to a reporter or an auditor. **Where a dependency's only available
fix requires Python 3.10 or later, the advisory is accepted as documented residual risk
with a named compensating control, rather than resolved by advancing the interpreter.**
Seven advisories across three packages are currently accepted on that basis.

Each of those seven is recorded in
[`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) with its unreachable
fix version, the measured Python 3.9 ceiling that puts the fix out of reach, the evidence
that the defect is unreachable in this codebase, and its compensating control. They are
not enumerated here, so that the register remains the one place they are maintained. A
report concerning any of them is welcome — please check the register first, because it may
already name the control that answers it.

## Reporting a Vulnerability

> **Do not open a public issue, pull request, or discussion for a suspected
> vulnerability.** Doing so discloses the weakness to everyone before a fix exists. Use a
> private channel below instead.

**Preferred channel — GitHub private vulnerability reporting.** Open the repository's
**Security** tab and choose **Report a vulnerability**. This creates an advisory visible
only to the maintainers and requires no email address.

**Alternative channel — email.** If private reporting is unavailable, use the project
maintainer address carried in [`README.md`](README.md): `your.email@example.com`. That
address is a placeholder, exactly as it is in the README; replace it with a monitored
mailbox before relying on this policy.

### What to include

A report is easiest to act on when it carries:

- The affected component or file path, and the branch or commit you observed it on.
- The impact — what an attacker gains, in terms of confidentiality, integrity, or availability.
- Reproduction steps, or a proof-of-concept, sufficient to confirm the finding.
- Any suggested remediation. Welcome, but never required.

### What to expect

These are response commitments, not fix commitments.

| Stage | Target |
| --- | --- |
| Acknowledgement that the report arrived | Within 5 business days |
| Initial assessment — in scope or not, plus a working severity | Within 10 business days |
| Status update while the report remains open | At least every 14 calendar days |

No fix-by date is promised, because the remediation effort cannot be known before the
assessment. The assessment states what is planned; the status updates state where it
stands.

### Disclosure

Please allow a remediation window before disclosing publicly. Ninety days from
acknowledgement is the default request, and a shorter window can be agreed for a finding
that is already public or trivially fixed. Credit is offered to anyone who reports
responsibly and wants it — say so in your report, and name the handle to use.

This project runs **no bug bounty** and offers no monetary reward.

## Scope

In scope for a security report:

- `backend/` — the API service, including its authentication, authorization, payment, and data-access code.
- `infrastructure/` — the container, Compose, and Terraform definitions.
- `scripts/` — the deployment and developer-setup automation.
- `.github/` — the continuous-integration and continuous-deployment workflows.

Out of scope:

- Findings that require an already-compromised host, or local filesystem access to the machine running the service.
- Volumetric denial of service — traffic floods and resource exhaustion driven by volume alone.
- The third-party services this system integrates with. Report issues in PayPal, Zillow, SendGrid, or Google Cloud to those providers directly.
- `frontend/` source, which the current change set treats as read-only reference material. A finding there cannot be fixed under this scope; it will be recorded rather than patched.

### Safe harbour

Good-faith research that stays within the limits below will not be pursued by this
project:

- No privacy violations. Do not access, retain, or exfiltrate anyone else's data.
- No destruction or corruption of data, and no degradation of service for others.
- Stop at the point of proving impact. Do not pivot further, escalate, or persist access once a finding is demonstrated.
- Report promptly, and observe the remediation window above.

This safe harbour covers **only environments you own or are explicitly authorized to
test**. It does not authorize testing against a deployment operated by anyone else, and it
cannot waive a third party's rights.

## Security Posture and Where It Is Documented

| Document | What it holds |
| --- | --- |
| [`docs/security/RESIDUAL_RISK.md`](docs/security/RESIDUAL_RISK.md) | The seven accepted advisories, their unreachable fix versions, the measured Python 3.9 ceilings, the reachability evidence, and each named compensating control. |
| [`docs/security/CREDENTIAL_ROTATION.md`](docs/security/CREDENTIAL_ROTATION.md) | The ordered runbook for credentials exposed through version control. |
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

### Previously committed credentials

**Credentials previously committed to this repository must be treated as compromised.**
Removing a secret from the current tree does not remove it from the repository's history,
and every existing clone, fork, mirror, and backup retains that history. Removal stops
future exposure; only revocation and rotation address exposure that has already happened.

This applies to the database connection string and the Google Cloud service-account key
reference formerly carried by `infrastructure/docker/docker-compose.yml`, and to the
placeholder signing key formerly written by `scripts/setup_dev_environment.sh`. All have
been removed from the working tree, and a root `.gitignore` and `.dockerignore` now
prevent reintroduction.

If you operate a deployment built from this repository, follow
[`docs/security/CREDENTIAL_ROTATION.md`](docs/security/CREDENTIAL_ROTATION.md). Its
sequence is revoke, then rotate, then delete from history, then review prior access, and
the order is load-bearing. Rotation cannot be rolled back.

## Verification Gates

The following gates run in continuous integration on every push and every pull request to
`main`, so a regression is caught rather than discovered. Anyone assessing a report can
run the same commands locally:

```bash
pip-audit -r backend/requirements.txt
bandit -r backend/app -ll
python -m pytest backend/tests/security -q
! pip show python-multipart
! grep -rEn "request\.form|request\.url|StaticFiles|HTTPEndpoint|Route\(|set_key|unset_key|\bclick\b" --include=*.py backend/
```

| Gate | Expected outcome |
| --- | --- |
| Dependency audit | Reports only the seven documented residual advisories, and nothing else. |
| Static analysis | No findings at Medium severity or above. |
| Security suite | Passes, including the forty-five-cell role matrix — nine routes against five principals, anonymous included. |
| Guard 1 — omitted package | `pip show` fails, because the package is deliberately absent from the manifest. |
| Guard 2 — advisory reachability | No match, so no accepted residual advisory has become reachable. |

The `-r backend/requirements.txt` argument to `pip-audit` is mandatory. A bare invocation
audits the whole environment and folds the audit tool's own dependency tree into the
report, which inflates the count and obscures which findings belong to this application.

The last two gates are the compensating controls for accepted residual advisories, made
executable so that the acceptance cannot lapse silently. Their leading `!` inverts the exit
status, because for both of them the desired result — the package is absent, the pattern
does not match — is what makes the underlying command exit non-zero.

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

Not every issue identified during security review has been fixed. Ten findings fell
outside the authorized change scope — several of them in `frontend/` source, which was
read-only for that work — and they are **reported and awaiting confirmation, not
resolved**. They are enumerated with their confirmation status in
[`docs/security/DECISION_LOG.md`](docs/security/DECISION_LOG.md) at row 34.6.3.

Please do not read this policy as a claim that the repository is free of known issues. It
is a claim that the known issues are written down, that each carries a stated disposition,
and that the gates above keep the resolved ones from regressing.
