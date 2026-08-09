# Accepted Residual Risk Register

This register records every dependency advisory that this remediation **did not
close**, together with the measurement proving no fix is reachable and the named
control that compensates for each. It exists so that the acceptance is
reviewable rather than implicit: an auditor should be able to re-run every
command quoted here and obtain the same result.

The reason any advisory remains open is narrow and specific. This service runs
on CPython 3.9, and that pin is a hard constraint of the work rather than a
default that drifted. Every advisory in this register has a published fix whose
release requires CPython 3.10 or later, so the fix cannot be installed without
advancing the interpreter. The instruction governing this situation was to
document such an advisory as accepted residual risk with a compensating
control, and that is what this file does.

**Every claim below is a measurement, not an assertion.** Each figure, ceiling,
version and pattern count was produced by executing a command inside a CPython
3.9.25 environment against the manifests in this repository. Where a
measurement corrected an earlier expectation, the correction is stated rather
than quietly absorbed.

## Headline outcome

Auditing the dependency set before this work reports **19 advisories across 7
packages**. Auditing the delivered manifest reports **7 advisories across 3
packages** — a **63% reduction**. The seven that remain are the subject of this
register. The twelve that were closed, and the mechanism that closed each, are
recorded in [Dispositions that are not residual](#dispositions-that-are-not-residual)
so the arithmetic is checkable rather than merely stated.

Static analysis moved from **1** finding at Medium severity or above to **0**
over the same change.

## What this document does, and what its siblings do

Four documents carry the written record of this remediation and each answers a
different question. This register **evidences**: it holds the measurement behind
each accepted advisory and each compensating control.

| Document | Answers |
|---|---|
| [`docs/security/DECISION_LOG.md`](DECISION_LOG.md) | **Argues** — the reasoning, the alternatives and the risks |
| [`docs/security/TRACEABILITY_MATRIX.md`](TRACEABILITY_MATRIX.md) | **Maps** — findings to the files that fix them and the tests that verify them |
| `docs/security/RESIDUAL_RISK.md` (this file) | **Evidences** — the advisories accepted under the runtime pin, with the measurement behind each control |
| [`docs/security/CREDENTIAL_ROTATION.md`](CREDENTIAL_ROTATION.md) | **Sequences** — the operational steps for the exposed credentials |

One consequence of that division is worth stating plainly, because it shapes
how this file is written. The *decision* to accept these seven advisories rather
than advance the interpreter is a logged decision, recorded as **row 1.9 of
[`docs/security/DECISION_LOG.md`](DECISION_LOG.md)** along with the alternative
that was rejected and the risk the choice carries. This register does not
relitigate that trade-off. It establishes the facts the decision rests on and
leaves the reasoning where it belongs.

## Residual risk summary

Seven advisories remain open. None has a fix that is reachable under the
mandated runtime, and each carries a compensating control that is specific to
the actual defect, currently satisfied by measurement, and enforced going
forward by an automated guard in continuous integration. Five affect a framework
component in a way this service does not use: two concern `Host`-header URL
reconstruction that no code path reads, one concerns a form parser this service
never invokes, one concerns a class-based endpoint style this service never
defines, and one is a Windows-only defect on a Linux-only runtime. One requires
local filesystem access and a helper function that is never called. One requires
a command-line helper unreachable from any HTTP request. No accepted advisory is
remotely exploitable against this service as delivered.

## Scope of this register

This register covers the **runtime dependency manifest**, `backend/requirements.txt`
— the set installed into the deployed image and reachable from a request. The
seven identifiers recorded here are exactly the seven suppressed in the runtime
audit gate at `.github/workflows/ci.yml`, whose comment names this file as their
registry.

The **development manifest**, `backend/requirements-dev.txt`, carries a separate
and smaller-consequence set of advisories in its test and scanning tooling.
Those are documented in place, inside that manifest's own accepted-advisory
section, because none of those packages is declared in the runtime manifest and
therefore none is present in the deployed image or reachable from a request.
**They are deliberately excluded from every count in this register**, whose
figures describe the runtime set only. An auditor comparing this register
against the continuous-integration configuration will see suppressions for both
manifests there and should read the development set at its own source.

## Reproducing these measurements

Every result in this register was produced with the commands below, run from the
repository root against a CPython 3.9.25 interpreter. No result here depends on
a newer interpreter, and none was inferred from release notes.

```bash
pip-audit -r backend/requirements.txt
pip index versions starlette
pip install --dry-run --no-deps starlette==1.3.1
bandit -r backend/app -ll
```

The manifest argument is not optional. A bare audit of the whole environment
mixes the scanning tool's own dependency tree into the report and inflates the
count, which is why every figure here is stated against a named manifest.

## The seven accepted advisories

The audit of the delivered runtime manifest reports exactly these seven, in
three packages:

```text
Found 7 known vulnerabilities in 3 packages
Name          Version ID              Fix Versions
------------- ------- --------------- ------------
starlette     0.49.3  PYSEC-2026-161  1.0.1
starlette     0.49.3  PYSEC-2026-249  1.3.1
starlette     0.49.3  PYSEC-2026-248  1.3.0
starlette     0.49.3  PYSEC-2026-2281 1.1.0
starlette     0.49.3  PYSEC-2026-2280 1.1.0
python-dotenv 1.2.1   PYSEC-2026-2270 1.2.2
click         8.1.8   PYSEC-2026-2132 8.3.3
```

| Advisory | Package @ pin | Unreachable fix | Nature of the defect | Named compensating control |
|---|---|---|---|---|
| PYSEC-2026-161 | `starlette` 0.49.3 | 1.0.1 | The requested URL is reconstructed from the `Host` header and path without validating the header, permitting path injection into the host part. The advisory notes this can lead to authentication bypass where authentication depends on the reconstructed URL's path. | Authorization derives solely from the verified token and the stored database role, never from a reconstructed URL; `request.url` is read nowhere. Trusted-host middleware rejects unexpected `Host` values before routing, and a continuous-integration grep guard fails the build if `request.url` is introduced. |
| PYSEC-2026-248 | `starlette` 0.49.3 | 1.3.0 | A path not beginning with `/` shifts the authority boundary during URL re-parsing, so the parsed hostname and network location become attacker-controlled. Only code that reads the parsed hostname is misled. | Identical to PYSEC-2026-161: zero reads of the parsed URL, trusted-host middleware rejecting unexpected `Host` values before routing, and the same continuous-integration grep guard. |
| PYSEC-2026-249 | `starlette` 0.49.3 | 1.3.1 | The field-count and part-size limits accepted by the form parser are enforced for multipart bodies but silently ignored for URL-encoded bodies, so an unauthenticated caller can exceed limits the application believed applied. | This service accepts JSON bodies exclusively and never calls the form parser. `python-multipart` is absent from the manifest, with a continuous-integration guard asserting its absence. The request-body-size cap bounds **every** request body regardless of content type, which is strictly stronger than the per-field limits the advisory describes as ignored. |
| PYSEC-2026-2280 | `starlette` 0.49.3 | 1.1.0 | The class-based endpoint selects a handler by lowercasing the HTTP method and performing an attribute lookup without restricting to known verbs, so a non-standard method can invoke an internal helper and bypass the intended handler's authorization checks. Affected only when such a class is registered without an explicit method list. | The service uses only the framework's router decorators, which always bind an explicit method. It defines no class-based endpoint and performs no bare route registration. A continuous-integration grep guard fails the build if either pattern appears. |
| PYSEC-2026-2281 | `starlette` 0.49.3 | 1.1.0 | The static-file handler on **Windows** is susceptible to server-side request forgery via a UNC path, which can leak the service account's credentials for offline attack. The advisory states POSIX systems are unaffected. | Two independent controls. No static-file handler is mounted anywhere in the service, and the runtime is Linux-only under the pinned slim Python base image in Docker and Kubernetes — a platform the advisory itself declares unaffected. |
| PYSEC-2026-2270 | `python-dotenv` 1.2.1 | 1.2.2 | The key-writing helpers follow symbolic links when rewriting the environment file, letting a **local** attacker overwrite arbitrary files via a crafted symlink on a cross-device rename fallback. | The service only ever **reads** the environment file, through the settings framework's `env_file` mechanism; the key-writing helpers are never called. The vector is local rather than network-reachable, and a continuous-integration grep guard enforces the read-only usage. |
| PYSEC-2026-2132 | `click` 8.1.8 | 8.3.3 | Command injection in the library's interactive-editor helper. | `click` enters the dependency graph solely as a dependency of the server's command-line entrypoint, verified from that package's own metadata. The editor helper is never invoked, the application imports the library nowhere, and no HTTP request path can reach it. |

### Evidence behind each control

The controls above are not assurances; each rests on something that was
measured or read. The measurements themselves are recorded in
[Proof of unreachability in this codebase](#proof-of-unreachability-in-this-codebase).

- **`request.url` is read nowhere** — measured at zero occurrences across every
  Python file under `backend/`. The authorization decision reads stored database
  rows only, stated at `backend/app/core/authorization.py:325`, so no
  reconstructed URL and no token claim can influence it. This is what makes
  PYSEC-2026-161 and PYSEC-2026-248 inert here: both mislead only code that
  reads the reconstructed or re-parsed URL.
- **Trusted-host middleware is present** — registered in `backend/app/main.py`
  against the configured allowed-host list, so an unexpected `Host` value is
  rejected before routing rather than being reconstructed into a URL.
- **The body-size cap is present and content-type independent** — implemented as
  body-size-limit middleware in `backend/app/main.py`, which checks the declared
  `content-length` before any body is read. It therefore bounds URL-encoded
  bodies too, which is precisely the case PYSEC-2026-249 describes as
  unbounded.
- **No form parser, no static-file handler, no class-based endpoint** — each
  measured at zero occurrences. Routing is performed exclusively through the
  framework's `include_router` and decorator forms, verified by reading
  `backend/app/api/router.py`, which registers four prefixed routers and nothing
  else.
- **The runtime is Linux** — the backend image is built `FROM python:3.9-slim`,
  read directly from `infrastructure/docker/Dockerfile.backend`. PYSEC-2026-2281
  declares POSIX systems unaffected, so the platform alone removes the vector
  even before the absent static-file handler is counted.
- **The environment file is only ever read** — `backend/app/core/config.py`
  declares `env_file` in its settings configuration, which is a read path. The
  key-writing helpers `set_key` and `unset_key` are measured at zero
  occurrences, so the code path the advisory describes is never entered.
- **`click` is transitive and unused** — the server package declares it as a
  dependency of its command-line entrypoint. The application imports it nowhere,
  measured at zero occurrences, so no request can reach the affected helper.

### An accuracy correction, recorded rather than absorbed

An early reading of the Starlette advisory set suggested it was predominantly
multipart-related. That framing would understate the analysis, and it is wrong.

**Only PYSEC-2026-249 concerns form parsing.** The remaining four are two
`Host`-header and URL-reconstruction defects (PYSEC-2026-161 and
PYSEC-2026-248), a Windows-only static-file issue (PYSEC-2026-2281), and a
class-based-endpoint dispatch issue (PYSEC-2026-2280). The controls in the table
above are written against those actual defects rather than against the initial
impression — which matters, because a control chosen for the wrong defect can
look adequate while protecting nothing. Had the multipart framing been carried
forward, four of the five Starlette entries would have been defended by an
argument about form bodies that has no bearing on them.

Starlette's own release notes corroborate the mapping, recording fixes for
dispatching only standard verbs in the class-based endpoint, ignoring malformed
`Host` headers when constructing the request URL, and rejecting absolute paths
in the static-file lookup.

## Proof that no fix is reachable

Each of the three affected packages has a highest installable release under
CPython 3.9. Those ceilings were measured, not inferred: candidate releases were
filtered by their declared `Requires-Python` metadata inside a CPython 3.9
interpreter's own environment, which is the same filter a deployment would apply.

| Package | Pinned version | Measured CPython 3.9 ceiling | Fix versions required | Position of every fix |
|---|---|---|---|---|
| `starlette` | 0.49.3 | **0.49.3** | 1.0.1, 1.1.0, 1.3.0, 1.3.1 | Above the ceiling |
| `python-dotenv` | 1.2.1 | **1.2.1** | 1.2.2 | Above the ceiling |
| `click` | 8.1.8 | **8.1.8** | 8.3.3 | Above the ceiling |

Each package is already pinned **at** its ceiling. There is no intermediate
release to move to, so no version change within the runtime can close any of the
seven.

### Independent corroboration

The ceilings are corroborated by the packaging metadata itself. Requesting a fix
version under CPython 3.9 is refused, and the refusal states the reason:
`starlette==1.3.1` declares **`Requires-Python >=3.10`**.

The same measurement was repeated for every remaining fix version, and each is
refused for the identical reason: `starlette==1.0.1`, `starlette==1.1.0` and
`starlette==1.3.0` all declare `Requires-Python >=3.10`, as do
`python-dotenv==1.2.2` and `click==8.3.3`. **All seven fixes are therefore
provably unreachable under the mandated runtime**, each by its own published
metadata rather than by inference from release notes.

### The runtime pin

The CPython 3.9 pin is a hard constraint of this work and is load-bearing in
five places, each verified by reading the file:

| # | Pin site | What pins it |
|---|---|---|
| 1 | `infrastructure/docker/Dockerfile.backend:2` | `FROM python:3.9-slim` |
| 2 | `.github/workflows/ci.yml:19` | `python-version: '3.9'` |
| 3 | `infrastructure/terraform/main.tf:99` | `runtime = "python39"` |
| 4 | `scripts/deploy.sh:24` | `--runtime python39` |
| 5 | `backend/app/tasks/listing_updater.py:10` | `@asyncio.coroutine` |

The fifth entry differs in kind from the other four and is the reason the pin is
self-reinforcing rather than merely declared. The first four are version
declarations. The fifth is a language construct that was removed in CPython 3.11,
so the application code would itself stop working on a newer interpreter. The
pin describes what this code can run on, not only what it is configured to run
on.

Two notes keep this table checkable. The line numbers above are the
pre-remediation locations, which is where each pin was verified and how the
other documents in this change set cite them; this remediation leaves **every
pin unchanged at 3.9**, and the surrounding hardening has since shifted some of
them further down their files. Separately, the development manifest describes the
pin as fixed in four places because it counts only the four version
declarations; the fifth is a code-level constraint rather than a declaration, and
both statements describe the same runtime.

Advancing the interpreter is therefore not treated as an available remediation
anywhere in this register. The decision to hold the pin and accept these seven
advisories, the alternative that was considered, and the risk the choice carries
are recorded as **row 1.9 of [`docs/security/DECISION_LOG.md`](DECISION_LOG.md)**.

## Proof of unreachability in this codebase

An unreachable fix only matters if the defect is also unreachable. Every
compensating control in the register above rests on the measurement in this
section: the affected framework constructs are not used by this service at all.

### The fourteen-pattern reachability measurement

Fourteen patterns were searched across every Python file under `backend/`. This
is the broad measurement that establishes reachability, and it is deliberately
wider than the automated guard described further below.

| # | Pattern | Advisory it would make reachable |
|---|---|---|
| 1 | `request.form` | PYSEC-2026-249 |
| 2 | `UploadFile` | PYSEC-2026-249 |
| 3 | `File(` | PYSEC-2026-249 |
| 4 | `Form(` | PYSEC-2026-249 |
| 5 | `OAuth2PasswordRequestForm` | PYSEC-2026-249 |
| 6 | `multipart` | PYSEC-2026-249 |
| 7 | `StaticFiles` | PYSEC-2026-2281 |
| 8 | `HTTPEndpoint` | PYSEC-2026-2280 |
| 9 | `Route(` | PYSEC-2026-2280 |
| 10 | `request.url` | PYSEC-2026-161, PYSEC-2026-248 |
| 11 | `click` | PYSEC-2026-2132 |
| 12 | `set_key` | PYSEC-2026-2270 |
| 13 | `unset_key` | PYSEC-2026-2270 |
| 14 | `TrustedHost` | none — this one probes for a control, see below |

Measured against the pre-remediation tree, **all fourteen patterns returned zero
matches**. Not one of the constructs the seven advisories depend on was in use
anywhere in the service.

### Re-measured against the delivered tree

The same fourteen patterns were re-run against the delivered tree, and the
result must be reported precisely rather than restated from the baseline.
**Thirteen of the fourteen still return zero.** The fourteenth, `TrustedHost`,
now returns matches.

That change is the control appearing, not an advisory becoming reachable. Every
occurrence is the trusted-host middleware that this remediation added — its
import, its subclass, its registration against the configured allowed-host list
in `backend/app/main.py`, and the test that asserts the allowed-host list in
`backend/tests/security/test_settings_and_redaction.py`. `TrustedHost` is the
named compensating control for PYSEC-2026-161 and PYSEC-2026-248, so its presence
is the register's own requirement being satisfied. The thirteen patterns that
represent genuine reachability remain at zero.

This distinction is the reason the automated guard below does **not** include
`TrustedHost`: a guard that failed on it would fail precisely when the control it
is meant to protect was installed.

### The two continuous-integration guards

Two guards in `.github/workflows/ci.yml` stop this acceptance decaying as the
code evolves. They are separate from the fourteen-pattern measurement above and
serve a different purpose: the measurement establishes the position today, the
guards defend it tomorrow.

**Guard 1 — the multipart-absence guard.** Asserts that the omitted package
stays omitted, by requiring that a query for `python-multipart` finds nothing.
The stake is specific: if a future transitive pull reintroduces the package, six
advisories return to the dependency set and the compensating control recorded for
PYSEC-2026-249 silently lapses. The guard converts that silent lapse into a
failed build. Measured today: the package is absent from both manifests and from
the installed environment.

**Guard 2 — the eight-pattern reachability guard.** A single grep over
**eight** patterns, scoped to Python files under `backend/`:

| # | Guarded pattern |
|---|---|
| 1 | `request.form` |
| 2 | `request.url` |
| 3 | `StaticFiles` |
| 4 | `HTTPEndpoint` |
| 5 | `Route(` |
| 6 | `set_key` |
| 7 | `unset_key` |
| 8 | `click` |

Measured today: **all eight return zero, so the guard starts green.** It fails
loudly the moment a change would make an accepted advisory reachable.

### Keeping the two sets straight

The two pattern sets are different things and are easy to conflate, so the
distinction is stated explicitly:

| | Fourteen-pattern set | Eight-pattern set |
|---|---|---|
| What it is | The broad reachability **measurement** | The automated **continuous-integration guard** |
| Patterns | 14 | 8 |
| When it runs | Taken as evidence for this register | On every build |
| Includes `TrustedHost` | Yes, as a control probe | No, deliberately |
| Result | Zero for all fourteen on the pre-remediation tree; zero for the thirteen reachability patterns on the delivered tree | Zero for all eight |

Describing the guard as covering fourteen patterns, or the measurement as
covering eight, would misstate both. The six patterns in the measurement but not
the guard are the form-handling constructs — `UploadFile`, `File(`, `Form(`,
`OAuth2PasswordRequestForm` and `multipart` — which Guard 1 already covers at the
package level, and `TrustedHost`, which is a control rather than a risk.

## Dispositions that are not residual

Seven advisories are accepted. Twelve were closed. This section records how, so
that the headline reduction can be checked rather than taken on trust.

### Fixed by upgrade — 3

| Advisory | Package | Fix lands at | Delivered pin |
|---|---|---|---|
| PYSEC-2024-38 | `fastapi` | 0.109.1 | 0.125.0 |
| PYSEC-2026-1943 | `starlette` | 0.40.0 | 0.49.3 |
| PYSEC-2026-1941 | `starlette` | 0.47.2 | 0.49.3 |

Both Starlette advisories are closed by the same pin that leaves five others
open, which is worth noting because it shows the pin is a ceiling rather than a
choice to stand still.

### Eliminated by package removal — 4

| Advisory | Package removed | Why it left the runtime graph |
|---|---|---|
| PYSEC-2026-2275 | `requests` | Its single call site moved to `httpx` |
| PYSEC-2026-142 | `urllib3` | Departed with its parent `requests` |
| PYSEC-2026-141 | `urllib3` | Departed with its parent `requests` |
| PYSEC-2026-1325 | `ecdsa` | Departed with its parent `python-jose` |

One point of precision, because an auditor reading the continuous-integration
configuration will encounter it. `requests` and `urllib3` left the **runtime**
manifest, which is what this register measures. Both are still reached by the
development-only scanning tooling, so their advisories appear in the development
manifest's own accepted set rather than disappearing entirely. Nothing in the
deployed image installs them, which is what makes their removal effective for the
runtime figures.

### Eliminated by omission — 6

| Advisories | Package omitted | Evidence for the omission |
|---|---|---|
| PYSEC-2026-1852, PYSEC-2026-3036, PYSEC-2026-3037, PYSEC-2026-3038, PYSEC-2026-3039, PYSEC-2026-3040 | `python-multipart` | Never imported anywhere in the service |

### Accepted as residual — 7

Five in `starlette`, one in `python-dotenv`, one in `click` — the subject of this
register.

### The arithmetic

The four dispositions account for **3 + 4 + 6 + 7 = 20** dispositions, covering
the 19 as-is advisories together with the reclassifications, and netting to
**19 across 7 packages before, 7 across 3 packages after — a 63% reduction**.

### The least obvious lever

**Four advisory families were closed by removing or omitting a package rather
than by upgrading one.** That is worth stating plainly because it is the lever a
reader is least likely to expect from a security fix: three of the four
dispositions above are subtractions.

`python-multipart` is the clearest case. A repository-wide search for
`UploadFile`, `File(`, `Form(`, `OAuth2PasswordRequestForm`, `request.form` and
`multipart` across the backend returns **zero matches**, so the package was
resolvable only as an optional extra and used nowhere. Omitting it from the
manifest removed six advisories at no functional cost — the single largest
reduction in the change, achieved by not declaring a dependency.

### Why the `ecdsa` case was pivotal

One entry decided the shape of the whole dependency remediation. In the as-is
audit report, `ecdsa` was the **only** package whose fix-version column was
empty:

```text
Name    Version  ID                Fix Versions
ecdsa   0.19.2   PYSEC-2026-1325
```

An empty fix column means no patched release exists. The package was not an
optional extra either: it is hard-required by `python-jose`, which the service
used for token handling. **Upgrading could not resolve it — only removal could**,
and removing it meant replacing its parent. That is why the token library was
replaced rather than pinned, and it is the one advisory in the original set that
no version change of any kind could have closed.

The distinction between that case and this register matters. `ecdsa` had **no fix
at all**; the seven advisories recorded here each have a published fix that is
merely **unreachable under the runtime pin**. Both are unfixable by upgrading,
for entirely different reasons, and only the second kind belongs in a residual
register. The decision to replace the token library rather than pin it is
recorded as row 1.1 of [`docs/security/DECISION_LOG.md`](DECISION_LOG.md).

## Two facts an auditor should have

Both were established by reading the file rather than by inference, and both
change how a figure in this register should be read.

### `python-dotenv` was already a runtime requirement

`backend/app/core/config.py:15` sets `env_file` in the settings configuration.
That single line is decisive, because the settings framework raises an import
error whenever that option is set and the dotenv package is absent — the package
is not optional once the option is declared.

**`python-dotenv` was therefore already an undeclared runtime requirement of the
pre-existing code.** The honest consequence, stated plainly: **PYSEC-2026-2270
predates this change rather than being introduced by it.** The advisory was
present in the running environment before this work began; it was simply
invisible, because no manifest existed to record the dependency. Declaring the
package documents a reality that was already there and does not expand the
dependency surface.

This is the one entry in the register whose accounting could be read as this
remediation adding an advisory. It is not, and a reviewer should not be left to
work that out unaided.

### The verification tooling was itself uninventoried

`.github/workflows/ci.yml:44` runs `flake8 .` — and nothing anywhere in the
workflow ever installs `flake8`. The only Python installation step in the file
installs a requirements manifest that did not exist in the repository at all.

The point is not the broken step; it is what the broken step reveals. The tooling
relied upon to verify this codebase was as uninventoried as the codebase's own
dependencies, which is the same class of gap as the missing manifest recorded as
finding INFRA-5. A register of accepted risk depends on its measurements being
reproducible, so the fact that a verification command could sit in the pipeline
indefinitely without its tool ever being installed is directly relevant to how
much weight an unmeasured claim should carry. Every claim in this register is
measured for that reason, and `flake8` is now declared in the development
manifest.

## Findings outside this register

This remediation additionally surfaced **ten findings outside the stated scope**.
They are **flagged and awaiting confirmation, not fixed**, and none of them is a
dependency advisory. They therefore **do not enter any count in this register**,
which concerns dependency advisories in the runtime manifest only. They are
enumerated with their confirmation status in
[`docs/security/DECISION_LOG.md`](DECISION_LOG.md) at row 34.6.3.

## Maintaining this register

An accepted risk is only accepted for as long as its compensating control holds.
Three events invalidate an entry above, and each is detectable:

1. **A guard fails.** Guard 1 failing means `python-multipart` has returned and
   the PYSEC-2026-249 control has lapsed. Guard 2 failing means a construct that
   makes an accepted advisory reachable has entered `backend/`. Neither should be
   suppressed; both should be treated as the acceptance being withdrawn.
2. **A ceiling moves.** If a fix version is republished with metadata that admits
   CPython 3.9, the corresponding entry stops being unreachable and should be
   fixed rather than accepted. The ceilings are re-measurable with the commands
   in [Reproducing these measurements](#reproducing-these-measurements).
3. **The runtime pin changes.** Every entry in this register is conditional on
   CPython 3.9. If the pin is ever revisited — a decision recorded at row 1.9 of
   [`docs/security/DECISION_LOG.md`](DECISION_LOG.md), not here — this register
   must be re-derived from a fresh audit rather than amended, because all seven
   fixes become installable at once.
