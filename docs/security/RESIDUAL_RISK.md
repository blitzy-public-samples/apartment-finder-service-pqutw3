# Accepted Residual Risk Register

This register records every dependency advisory that this remediation **did not
close**, together with the measurement proving no fix is reachable and the named
control that compensates for each. It exists so that the acceptance is
reviewable rather than implicit: an auditor should be able to re-run every
command quoted here and obtain the same result.

The reason any advisory remains open is narrow and specific, and it is **not the
same reason for all seven**. This service runs on CPython 3.9, and that pin is a
hard constraint of the work rather than a default that drifted. Every advisory in
this register has a published fix whose release declares
`Requires-Python >=3.10`, so no fix can be installed without advancing the
interpreter. For two of the seven that is the whole story. For the five in
`starlette` a **second, independent** constraint applies as well: the delivered
FastAPI pin will not accept a `starlette` release in the range the fixes occupy,
and the FastAPI pin is itself set by holding Pydantic at version 1, which this
work is instructed not to change. [Proof that no fix is
reachable](#proof-that-no-fix-is-reachable) states both constraints per package
and measures each.

The instruction governing this situation was to document such an advisory as
accepted residual risk with a compensating control, and that is what this file
does. It is stated this way deliberately: a reader who took "the interpreter is
the only barrier" at face value would plan a runtime upgrade and find five of the
seven still open afterwards.

**Every claim below is a measurement, not an assertion.** Each figure, ceiling,
version and pattern count was produced by executing a command inside a CPython
3.9.25 environment against the manifests in this repository. Where a
measurement corrected an earlier expectation, the correction is stated rather
than quietly absorbed.

## Headline outcome

Auditing the dependency set before this work reports **19 advisories across 7
packages**. Auditing the delivered manifest reports **7 advisories across 3
packages** — a **63% reduction**. Those figures describe the runtime
manifest, and the seven that remain are the subject of the
[Runtime register](#runtime-register-seven-accepted-runtime-advisories). The
twelve that were closed, and the mechanism that closed each, are recorded in
[Dispositions that are not residual](#dispositions-that-are-not-residual) so the
arithmetic is checkable rather than merely stated.

The development manifest carries **1 advisory in 1 package**, in test tooling that
no deployed process installs. It is recorded in the
[Development register](#development-register-one-accepted-development-advisory).
**Eight identifiers are suppressed in total** across the two audit invocations,
and [The total-suppression accounting](#the-total-suppression-accounting)
reconciles that figure against both registers.

That figure was fourteen until this round, when the audit instrument was moved out
of the audited development manifest into `backend/requirements-audit.txt`. Six of
the seven advisories the Development register then carried were `pip-audit`'s own
supply chain rather than anything this repository tests or ships;
[The audit instrument's own tree](#the-audit-instruments-own-tree) records the
measurement and what bounds the instrument's exposure.

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
how this file is written. The *decision* to accept these eight advisories
rather than advance the interpreter is a logged decision, recorded as **row 1.9 of
[`docs/security/DECISION_LOG.md`](DECISION_LOG.md)** along with the alternative
that was rejected and the risk the choice carries. This register does not
relitigate that trade-off. It establishes the facts the decision rests on and
leaves the reasoning where it belongs.

## Residual risk summary

Seven advisories remain open. None has a fix that is reachable under the
mandated runtime, and each carries a compensating control that is specific to
the actual defect, currently satisfied by measurement, and partly enforced going
forward by an automated guard in continuous integration. Five affect a framework
component in a way this service does not use: two concern `Host`-header URL
reconstruction that no code path reads, one concerns a form parser this service
never invokes, one concerns a class-based endpoint style this service never
defines, and one is a Windows-only defect on a Linux-only runtime. One requires
local filesystem access and a helper function that is never called. One requires
a command-line helper unreachable from any HTTP request.

### What the evidence establishes, and what it does not

This is a **conditional reachability analysis**, not a proof of
non-exploitability, and the difference matters enough to state before the
evidence rather than after it. Each entry below establishes that **the
precondition the advisory depends on is absent from this service as delivered**.
That is a claim about a measured state of the tree, the manifest and the runtime
platform on the date recorded — not a claim that the defect is harmless, that the
advisory has been analysed exhaustively, or that no future change can make it
reachable.

Four assumptions carry every entry. Each is checkable, and each is a thing that
could stop being true:

1. **The measurement is complete for the pattern set chosen.** Reachability was
   established by searching fourteen named constructs across `backend/`. A
   reachable path that uses none of those fourteen constructs would not have been
   found. The set was derived from each advisory's own description, which is the
   best available basis and is still a judgement.
2. **The advisory descriptions are complete.** Each control is written against
   the defect as published. If an advisory is later amended to describe a wider
   condition, the control written against the narrower one may no longer answer
   it — this register has already been corrected once on exactly that account,
   recorded in [An accuracy correction](#an-accuracy-correction-recorded-rather-than-absorbed).
3. **The deployed platform is the one measured.** PYSEC-2026-2281's control rests
   in part on a Linux runtime. It does not hold for a Windows host, and nothing in
   the pipeline enforces the platform.
4. **Dependency resolution stays where it is measured.** The transitive graph was
   read at the delivered pins. A future resolution that pulls a different set
   changes the premise, and only one part of that — the omission of
   `python-multipart` — is guarded automatically.

The automated guards are narrower than the analysis, and should not be read as
covering it. Together they assert exactly two things: that one named package
remains absent from the environment, and that eight named source patterns return
zero matches under `backend/`. They do **not** check the platform, the transitive
graph beyond that one package, the six form-handling patterns outside the guard
set, anything outside `backend/`, or whether an advisory's description has
changed. [The two continuous-integration guards](#the-two-continuous-integration-guards)
states their coverage precisely, and
[Keeping the two sets straight](#keeping-the-two-sets-straight) states what the
guard omits relative to the measurement.

**Residual uncertainty is therefore retained, deliberately.** The honest summary
is that no accepted advisory has a precondition satisfied by this service as
measured; that assumptions 1 and 4 are **partly** machine-checked — Guard 2 covers
eight of the fourteen patterns, Guard 1 covers one package of the graph — while
assumptions 2 and 3 are checked by nobody and nothing; and that an accepted
advisory should be re-derived rather than assumed whenever
[Maintaining this register](#maintaining-this-register) names a triggering event.

**One further residual risk is registered here and is not one of the seven.** It is
operational rather than exploitable: the pinned interpreter is no longer offered by the
provider's managed serverless runtime, so that hosting option is closed at this version.
It carries no confidentiality, integrity or availability exposure for the delivered
service — the service does not run there — but it does remove a deployment path the
infrastructure previously claimed, and a reader assessing operational readiness needs it.
See [The runtime pin's second consequence](#the-runtime-pins-second-consequence-a-decommissioned-hosting-runtime).

One **development** advisory remains open alongside them, in the test framework.
Its fix is unreachable for the same reason and its compensating control is
stronger, because the package is not declared in the runtime manifest and so is
not installed into the deployed image or reachable from any request at all. It is
the subject of the
[Development register](#development-register-one-accepted-development-advisory).

| | Runtime | Development | Total |
|---|---|---|---|
| Manifest | `backend/requirements.txt` | `backend/requirements-dev.txt` | both |
| Advisories accepted | 7 | 1 | **8** |
| Packages affected | 3 | 1 | 4 |
| Present in the deployed image | Yes | No | |
| Reachable from a request | No, by compensating control | No, by absence | |

**Eight** is therefore the number of identifiers a reader will count in the audit
gate, and it is the sum of two registers rather than a single accepted set.

## Scope: two registers, eight suppressions

Two manifests are audited, so this file carries two registers and one shared
accounting. Neither register is a subset of the other and neither is documented
elsewhere: **every identifier suppressed anywhere in continuous integration is
recorded in this file**, which is the property that makes the audit gate's own
comment true.

| Register | Manifest | Identifiers | Where the audit runs |
|---|---|---|---|
| [Runtime](#runtime-register-seven-accepted-runtime-advisories) | `backend/requirements.txt` | 7 | `.github/workflows/ci.yml` and `.github/workflows/cd.yml` |
| [Development](#development-register-one-accepted-development-advisory) | `backend/requirements-dev.txt` | 1 | the same two gates, as a second invocation |
| **Total** | both | **8** | |

**A third manifest exists and is deliberately not audited.**
`backend/requirements-audit.txt` declares the audit instrument itself,
`pip-audit`, and nothing else. `pip-audit` resolves a dependency tree of its own
through `CacheControl[filecache]` — `msgpack`, `requests`, `urllib3` and
`filelock` — and every advisory in that tree is reported when the manifest
declaring it is audited. Declared beside the test and lint tooling, as it was
until this round, the instrument's own tree was counted as this project's
accepted development risk: six of the seven identifiers formerly in the
Development register belonged to `pip-audit`, not to anything this repository
tests or ships. Declared apart, it is counted as what it is. The instrument is
installed by the gate, is present in no image and in no audited resolution, and
is the subject of
[The audit instrument's own tree](#the-audit-instruments-own-tree) below.

The split is not cosmetic. A runtime advisory sits in a package that is installed
into the deployed image and could in principle be reached by an HTTP request, so
its compensating control has to argue that the specific defective code path is
never taken. A development advisory sits in a package that no deployed process
installs, so its compensating control is the absence itself. Merging the two into
one figure would apply the weaker argument to the stronger case and the stronger
to the weaker, so each register carries its own evidence and the total is stated
beside both.

An auditor comparing this file against the continuous-integration configuration
should find an exact set match in each direction: the seven identifiers in the
runtime audit invocation against the Runtime register, the one in the development
invocation against the Development register, and no ninth identifier anywhere.
Two tests in `backend/tests/security/test_release_automation_contract.py` assert
precisely that, so a suppression added to a workflow without a register entry
fails the build.

### What the runtime register covers

The runtime register covers the **runtime dependency manifest**,
`backend/requirements.txt`, which is the set installed into the deployed image and
reachable from a request. The seven identifiers recorded there are exactly the
seven suppressed by the runtime audit invocation in `.github/workflows/ci.yml`,
repeated in `.github/workflows/cd.yml`, whose comments name this file as their
registry.

The **development manifest**, `backend/requirements-dev.txt`, carries a separate
set of one advisory in its test framework. Where it is documented was an open
question between this register and the decision log, and it is now settled by a
single recorded decision — **row 35.3 of
[`docs/security/DECISION_LOG.md`](DECISION_LOG.md)** — which this section states
and does not relitigate:

- **This register is the index of every accepted advisory, runtime and
  development.** The [development-manifest advisory](#the-development-manifest-advisory)
  section below lists it by identifier, package, unreachable fix and route into
  the graph, so an auditor comparing this file against the pipeline's two
  suppression lists finds both sets here.
- **The manifest header remains the authority for its detail.** The full
  compensating-control argument for the development set lives in
  `backend/requirements-dev.txt`'s own accepted-advisory section, beside the pins
  it governs, and is not duplicated here. A duplicate would be a second place to
  keep in agreement.
- **The two sets are counted separately and never added together.** Every
  headline figure in this register — the nineteen, the seven, the 63% — describes
  the **runtime** manifest alone, because that is the set installed into the
  deployed image and reachable from a request. The development package is not
  declared in the runtime manifest.

## Reproducing these measurements

Every result in this register was produced with the commands below, run from the
repository root against a CPython 3.9.25 interpreter. No result here depends on
a newer interpreter, and none was inferred from release notes.

```bash
pip-audit -r backend/requirements.txt
pip-audit -r backend/requirements-dev.txt
pip index versions starlette
pip install --dry-run --no-deps starlette==1.3.1
python -c "import importlib.metadata as m; print([r for r in m.requires('fastapi') if 'starlette' in r or 'pydantic' in r])"
bandit -r backend/app -ll
```

The fifth command is the one that establishes
[Constraint 2](#constraint-2--the-framework-resolver-which-applies-to-the-five-in-starlette).
Reading it against the installed `fastapi` prints the bound the delivered pin
places on `starlette`; reading the same field from a downloaded `fastapi` 0.128.8
wheel prints the bound the highest CPython-3.9-installable release places on it,
together with its Pydantic requirement.

The manifest argument is not optional. A bare audit of the whole environment
mixes the scanning tool's own dependency tree into the report and inflates the
count, which is why every figure here is stated against a named manifest. Both
manifests are audited, because the register indexes both sets.

## Runtime register: seven accepted runtime advisories

This is the register the runtime invocation of the audit gate is measured
against, and it covers `backend/requirements.txt` alone. The audit of that
manifest reports exactly these seven, in three packages:

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

Two independent constraints put these fixes out of reach, and an accurate account
of this register needs both. The first applies to all seven. The second applies
to the five in `starlette` and would still apply on a newer interpreter.

### Constraint 1 — the interpreter ceiling, which applies to all seven

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
release to move to, so no version change within the runtime manifest can close
any of these seven.

### Constraint 2 — the framework resolver, which applies to the five in `starlette`

`starlette` is not a package this service selects freely. It is the ASGI
foundation FastAPI declares a bounded requirement on, so the acceptable range is
whatever the delivered FastAPI pin permits — and the delivered FastAPI pin is
itself fixed by holding Pydantic at version 1, which this work is instructed not
to change. Both bounds were read from installed and downloaded package metadata:

| Read from | Declares | Consequence for the five `starlette` advisories |
|---|---|---|
| `fastapi` 0.125.0 — the delivered pin, at `backend/requirements.txt` | `starlette<0.51.0,>=0.40.0` and `pydantic>=1.7.4,<3.0.0` | Every fix version is `1.x`, above `0.51.0`. The delivered pin **cannot** accept any of them, on any interpreter. |
| `fastapi` 0.128.8 — the highest FastAPI installable under CPython 3.9 | `starlette<1.0.0,>=0.40.0` **and** `pydantic>=2.7.0` | Still excludes every `1.x` fix, **and** requires Pydantic v2, which is frozen at v1 by the change scope. |

Two things follow, and the second is the one an upgrade plan needs.

First, **FastAPI is held at 0.125.0 because of Pydantic, not because of Python.**
The interpreter independently caps FastAPI at 0.128.8; Pydantic v1 caps it lower,
at 0.125.0. So the FastAPI pin is not staleness, and raising the interpreter does
not raise it.

Second, **closing any of the five `starlette` advisories requires three changes
at once, not one.** A newer interpreter, a FastAPI release whose declared range
admits `starlette` 1.x, and Pydantic v2 to satisfy that FastAPI release. Only the
first is a runtime decision; the second and third are a framework migration
across a major version of the validation library that every request and response
model in this service is written against.

`python-dotenv` and `click` are different, and the register says so rather than
generalising. `python-dotenv` is a direct pin no other package bounds, and
`click` arrives solely as a dependency of the ASGI server's command-line
entrypoint, which declares only `click>=7.0` — so `click` 8.3.3 would satisfy it.
For those two the interpreter genuinely is the sole barrier.

### Independent corroboration

The interpreter ceilings are corroborated by the packaging metadata itself.
Requesting a fix version under CPython 3.9 is refused, and the refusal states the
reason: `starlette==1.3.1` declares **`Requires-Python >=3.10`**.

The same measurement was repeated for every remaining fix version, and each is
refused for the identical reason: `starlette==1.0.1`, `starlette==1.1.0` and
`starlette==1.3.0` all declare `Requires-Python >=3.10`, as do
`python-dotenv==1.2.2` and `click==8.3.3`. **All seven fixes are therefore
unreachable under the mandated runtime**, each by its own published metadata
rather than by inference from release notes — and the five in `starlette` remain
unreachable under Constraint 2 even once that metadata stops refusing them.

### The runtime pin

The CPython 3.9 pin is a hard constraint of this work. It is load-bearing in
**five** places in the delivered tree — four version declarations and one code-level
constraint — each verified by reading the file, and it is unchanged from the baseline.
**This table is the single authoritative inventory**, named as such by every sibling
document, and row 91.2.1 of the decision log records the measurement behind it.

| # | Pin site | What pins it |
|---|---|---|
| 1 | `infrastructure/docker/Dockerfile.backend:1` | `FROM python:3.9-slim` |
| 2 | `.github/workflows/ci.yml:108` | `python-version: '3.9'` |
| 3 | `infrastructure/terraform/main.tf:384` | `runtime = "python39"` |
| 4 | `scripts/deploy.sh:889` | `--runtime python39` |
| 5 | `backend/app/tasks/listing_updater.py:329` | `@asyncio.coroutine` |

So the delivered pin is **four version declarations plus one code-level constraint**:
entries 1 to 4 are configuration and entry 5 is a language construct. `.github/workflows/ci.yml`
declares the interpreter in five jobs and is counted once as one file.

**One intermediate count is superseded, and is stated so that a citation of it lands
here.** `docs/security/DECISION_LOG.md` §82.27.1 withdrew row 1.9's five-site list and
published **three** — two declarations plus the code constraint — on the ground that
§82.1 had deleted both the managed-function resource in `infrastructure/terraform/main.tf`
and the runtime flag in `scripts/deploy.sh`. That was accurate for the tree it measured.
A later round reinstated both behind an authorization gate rather than deleting them, so
the tree carries four declarations again, and row 91.2.1 is the current authority. Every
sibling document states **five**, and so does this table.

The fifth entry differs in kind from the version declarations and is the reason the
pin is self-reinforcing rather than merely declared: it is a language construct removed
in CPython 3.11, so the application code would itself stop working on a newer
interpreter, whatever the configuration said. The pin describes what this code can run
on, not only what it is configured to run on — and that entry was re-verified by
execution rather than by reading, because the delivered ingestion workload now invokes
that coroutine directly from a scheduled job: the exact command that job runs was
executed under CPython 3.9.25 and exited 0.

Two notes keep this table checkable. **The line numbers above are the delivered
locations**, each re-read from this tree rather than carried over from the plan, and each
one resolves: `FROM python:3.9-slim` on line 1, `python-version: '3.9'` on line 108,
`runtime = "python39"` on line 384, `--runtime python39` on line 889 and
`@asyncio.coroutine` on line 329. Entry 4 moved during the round that added the release
script's port-forward teardown and its pre-flight token check, from line 768 to line 889 of
`scripts/deploy.sh`; row 102.2.5 of the decision log records that renumbering and lists the
withdrawn location. That location is named in prose rather than as a path-and-line citation,
because `backend/tests/security/test_deployment_contract.py` reads every citation of that
shape in this file and opens the line it names, so quoting a withdrawn number in that form
would send the gate &mdash; and a reviewer with it &mdash; to a line that no longer carries the
pin. The locations the plan states &mdash; Dockerfile line 2, workflow line 19,
Terraform line 99, release-script line 24 and task line 10 &mdash; are the
**pre-remediation** ones and no longer resolve, because the surrounding hardening moved
each declaration further down its file; what has not changed is the version itself, since
this remediation leaves **every surviving pin unchanged at 3.9**. Separately,
[`README.md`](../../README.md) is the other document that publishes the count, as "the
Python 3.9 pin is a hard constraint and is load-bearing in five places" followed by the
five files without line numbers; every sibling document cites this table for the locations,
so there is one inventory and this section is where it is maintained. The development
manifest names the interpreter in its header and states no count at all, which is
deliberate: a manifest that restated the inventory would be a second place to keep it in
step. Four of the five are version declarations &mdash;
`infrastructure/docker/Dockerfile.backend`, `.github/workflows/ci.yml`,
`infrastructure/terraform/main.tf` and `scripts/deploy.sh` &mdash; and the fifth is the
`@asyncio.coroutine` construct in `backend/app/tasks/listing_updater.py`, which pins the
interpreter in code rather than in configuration. The delivery workflow declares no
interpreter of its own: it calls the verification workflow, so the pin governs both runs
from one declaration and cannot drift between them. That was re-verified for this
correction by searching `.github/workflows/cd.yml` for any interpreter declaration at
baseline and as delivered, and finding none in either.

One further file names the version without pinning a delivered artefact, and it is
recorded here so the inventory is exhaustive about what an interpreter change must
touch: `scripts/setup_dev_environment.sh:21` sets `REQUIRED_PYTHON_VERSION="3.9"` and
refuses to build a developer environment on any other interpreter. It is deliberately
not one of the five, because it configures neither a delivered artefact nor a
verification run — but anyone raising the interpreter has to edit it as well, or every
developer environment refuses to build while every deployed artefact succeeds.

Advancing the interpreter is therefore not treated as an available remediation
anywhere in this file. The decision to hold the pin and accept all eight
advisories, the alternative that was considered, and the risk the choice carries
are recorded as **row 1.9 of [`docs/security/DECISION_LOG.md`](DECISION_LOG.md)**,
whose site list that log's §35.27.1 supersedes.

## The runtime pin's second consequence: a decommissioned hosting runtime

Everything above concerns library fixes that the pin puts out of reach. The pin has a
second consequence that this register previously did not carry at all, and it is the
more operationally significant of the two: **a hosting platform the infrastructure
named is no longer available at the pinned version.**

This is registered as accepted residual risk under the same instruction that governs
the seven advisories — where the only fix requires a newer runtime, document it with a
compensating control rather than advance the interpreter — but it is a different kind
of risk and is counted separately.

### The constraint

| Attribute | Statement |
|---|---|
| **What** | The provider's managed serverless functions product retired its Python 3.9 runtime |
| **When** | 5 April 2026. This register was last measured on 9 August 2026, so the date is **past**, not upcoming |
| **Effect after the date** | Under that provider's runtime-support policy, a retired runtime can no longer be used to create or update a function, and existing deployments on it become liable to be disabled |
| **Where it applies here** | `infrastructure/terraform/main.tf:384` declares a function with `runtime = "python39"` and `scripts/deploy.sh:889` passes `--runtime python39` — pin sites 3 and 4 of the table above. Both are **withheld rather than removed**: the resource and its invoker binding each carry `count = var.cloud_function_deployment_authorized ? 1 : 0`, which defaults to `false`, and the script refuses the deploy step unless `CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED=true`. So the declaration exists, is reviewable, and no apply or release attempts a create that the provider would refuse |
| **Why it could not be fixed by upgrading the runtime** | The pin is a hard constraint, and pin site 5 makes it more than a preference: `@asyncio.coroutine` was removed in CPython 3.11, so the ingestion code would break on the newer runtimes the product still offers |

### The evidence behind withholding the resource rather than applying or deleting it

Three facts about the **baseline** resource were read from the repository rather than
assumed, and together they establish that nothing usable was being deployed:

1. **There was no function source.** The resource named an archive `function-source.zip`
   that existed nowhere in the repository, and no `functions/` directory existed.
2. **There was no entry point.** It named `hello_world`, which no module in this
   repository defined, and it carried the display name "My function".
3. **Nothing scheduled the workload it purported to run.** `run_listing_updater()` was
   referenced by no scheduler — the application's lifespan created no task — so the
   periodic ingestion the function was nominally for was not running anywhere.

A resource naming a decommissioned runtime, a source archive that does not exist and an
entry point that is not defined is a broken claim rather than a deployment.

**All three are addressed in the delivered tree, and the runtime is still the blocker.**
The source is real: `data.archive_file.function_source` packages
`infrastructure/functions/health/`, which carries `main.py` and its own pinned
`requirements.txt`. The entry point, the name and the description are variables with
validation rather than placeholders. And the ingestion schedule the function was
nominally for is a delivered CronJob, described below. What remains unresolvable inside
this scope is the runtime identifier itself, so the resource is **withheld** — declared
and reviewable, excluded from every plan until a release owner authorizes either a
supported runtime or the function's retirement. Row 91.6.3 records the invoker form the
declaration uses, and the escalation is stated in the configuration beside the resource.

### The alternative strategy adopted

The workload is re-expressed on a platform where the pin is preserved rather than
fought: a Kubernetes **CronJob** at `infrastructure/kubernetes/65-ingestion-cronjob.yaml`, running
`update_listings()` hourly on the same `python:3.9-slim` backend image the served
workload uses, with `concurrencyPolicy: Forbid` so a slow pass cannot overlap the next.
Pin site 1 — the image's own base — is what preserves the interpreter, so the schedule
moved and the runtime did not.

**Verified by execution rather than by review:** the exact command the CronJob runs was
executed under CPython 3.9.25 in this working tree and exited 0, emitting one structured
ingestion-pass record. That simultaneously confirms the workload functions and that the
`@asyncio.coroutine` construct of pin site 5 remains callable on the pinned interpreter.
The same command was then run against a provider read that could not be completed and
exited **non-zero**, which is what makes the schedule's `backoffLimit` and its failed-job
history meaningful; O-8 records why that outcome had to be corrected.

### Compensating position, and what remains open

| Aspect | Position |
|---|---|
| **Exposure to the running service** | None. The service does not run on the retired product, and no request path reaches it |
| **Compensating control** | The declaration is gated closed by default in both delivery paths — `var.cloud_function_deployment_authorized` in Terraform and `CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED` in `scripts/deploy.sh`, each defaulting to `false` — so no apply and no release attempts a create the provider would refuse, and the conflict is visible in the configuration rather than discovered at the API. An absence sweep over all three Terraform files and both delivery paths reports zero occurrences of the phantom source archive, the placeholder entry point and the placeholder display name; the retired runtime identifier remains, deliberately, because the pin forbids changing it and the gate is what makes that safe |
| **Residual operational risk** | A managed function may still exist in a live project from an earlier apply, carrying an anonymous invoker binding that neither withholding the resource nor removing it would revoke. This is handled as an explicit, idempotent revocation step in `scripts/deploy.sh` and is called out for the operations reviewer in [`docs/review/CRITICAL_DECISIONS.md`](../review/CRITICAL_DECISIONS.md) |
| **Forward-compatibility debt** | Pin site 5 will fail on CPython 3.11 or later. It is retained deliberately, is among the findings reported for confirmation rather than fixed, and is the reason the pin is self-reinforcing. It is the item to discharge first if the pin is ever lifted |
| **Reasoning and alternatives** | `docs/security/DECISION_LOG.md` §35.1, which records four rejected alternatives — advancing the runtime, keeping the resource ungated and noting the issue, commenting the resource out, and migrating to a second-generation function or container service |

One clarification the pin table invites, stated so it is not inferred wrongly:
lifting the pin would make `python-dotenv` 1.2.2 and `click` 8.3.3 installable
and would close **two** of the seven. It would not close the other five, because
Constraint 2 does not depend on the interpreter. An upgrade plan built on this
register should size the `starlette` five as a framework migration and the other
two as a pin bump.

## Proof of unreachability in this codebase

An unreachable fix only matters if the defect is also unreachable. Every
compensating control in the register above rests on the measurement in this
section: the affected framework constructs are not used by this service at all.

### The fourteen-pattern reachability measurement

Fourteen patterns were searched, case-sensitively, across every Python file
under `backend/`. This is the broad measurement that establishes reachability,
and it is deliberately wider than the automated guard described further below.
Two scopes appear in this section and every result below names the one it holds
for: `backend/` is the application package and the test suite together, and
`backend/app/` is the application package alone, which is the only one of the two
the runtime image installs.

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
matches**. Not one of the constructs the seven runtime advisories depend on was
in use anywhere in the service.

### Re-measured against the delivered tree

The same fourteen patterns were re-run against the delivered tree, and the
result must be reported precisely rather than restated from the baseline. The two
scopes give different answers, and only one of them bears on reachability, so
each is reported with the scope it holds for.

**At `backend/app/`, thirteen of the fourteen return zero.** The fourteenth,
`TrustedHost`, matches. Nothing an HTTP request can reach names any of the other
thirteen constructs.

**An earlier revision of this subsection reported that result while declaring the
scope `backend/`, where it is not true.** The conclusion was sound and the
evidence as written was not, which is the correction recorded at row 96.2.1 of
[`docs/security/DECISION_LOG.md`](DECISION_LOG.md).

**At `backend/`, most of the fourteen match, and no count is published for that
scope.** Every match outside `backend/app/` lies under `backend/tests/`, and
every one of them is a test naming a construct in order to assert its absence
rather than a use of it. They are concentrated in
`backend/tests/security/test_residual_risk_guards.py`, which holds the pattern
set as string literals and parses sources that use each construct so that its
detection can be asserted to work; the remainder sit in the modules that assert
the trusted-host list and the guard wording. A module that names a construct in
order to prove the application does not use it is evidence for this register
rather than against it, and none of those modules is installed into the runtime
image: the backend container installs `backend/requirements.txt` only and copies
no test tree.

**No count is published at the wider scope because a published one could not
stay true.** The assertion that holds this section honest necessarily names all
fourteen patterns as literals, which changes any `backend/`-wide tally the moment
it is written — as it did: a first attempt published four-of-fourteen at zero and
was falsified by its own assertion. What is asserted instead is the property this
register actually rests on, which is stable: thirteen of the fourteen return zero
across `backend/app/`, and **no match anywhere under `backend/` sits outside
`backend/app/` and `backend/tests/`.**

`TrustedHost` is the one construct whose matches are a use rather than an
assertion, and it matches at both scopes. That is the control appearing, not an
advisory becoming reachable: the occurrences are the trusted-host middleware
this remediation added — its import, its subclass and its registration against
the configured allowed-host list in `backend/app/main.py` — plus the test that
asserts that list in
`backend/tests/security/test_settings_and_redaction.py`. `TrustedHost` is the
named compensating control for PYSEC-2026-161 and PYSEC-2026-248, so its
presence is the register's own requirement being satisfied.

**What this means for the seven acceptances.** Each rests on the application
package not using the affected construct, and at `backend/app/` that is exactly
what the thirteen zeroes say. The wider scope adds no reachable use: it adds the
guard fixtures that keep the acceptance honest, and they run in no image.

This distinction is the reason the automated guard below does **not** include
`TrustedHost`: a guard that failed on it would fail precisely when the control it
is meant to protect was installed. It is also why that guard is scoped to
`backend/app/` — under the wider scope its own test fixtures would fail it, which
is the same effect, reported at length in the next section.

`backend/tests/security/test_residual_risk_guards.py` asserts both statements
above against a live measurement of the tree — the thirteen zeroes at
`backend/app/`, and that no match anywhere under `backend/` sits outside
`backend/app/` and `backend/tests/` — so neither can drift from what a reader
would measure.

### The two continuous-integration guards

Two guards in `.github/workflows/ci.yml` slow this acceptance decaying as the
code evolves. They are separate from the fourteen-pattern measurement above and
serve a different purpose: the measurement establishes the position today, the
guards defend part of it tomorrow.

**What the two guards cover, stated before they are described.** Between them
they assert exactly two facts: one named package is absent from the installed
environment, and eight named patterns return no match in Python files under
`backend/`. Everything else an entry in this register rests on is unguarded — the
runtime platform, the six form-handling patterns outside Guard 2, any code outside
`backend/`, the transitive graph beyond that one package, and the wording of the
advisories themselves. They are a tripwire on the two most likely regressions, not
a proof that the acceptance still holds.

**Guard 1 — the multipart-absence guard.** Asserts that the omitted package
stays omitted, by requiring that a query for `python-multipart` finds nothing.
The stake is specific: if a future transitive pull reintroduces the package, six
advisories return to the dependency set and the compensating control recorded for
PYSEC-2026-249 silently lapses. The guard converts that silent lapse into a
failed build. Measured today: the package is absent from both manifests and from
the installed environment.

**Guard 2 — the reachability guard, in two layers.** Guard 2 is a textual
pre-filter and a semantic assertion, and it is worth being precise about which
one does what, because the pre-filter alone does less than its shape suggests.

*Layer one — the textual pre-filter.* A single grep over **eight** patterns,
scoped to Python files under `backend/app/`:

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

Measured today: **all eight return zero, so the pre-filter starts green.**

**Its scope is `backend/app/` and not `backend/`.** That is the application
package — the code an HTTP request reaches, and the only tree
`backend/requirements.txt` puts into the runtime image. Nothing under
`backend/tests/` is installed into that image, so a test module that *names* one
of these constructs in order to assert its absence is not a reachable use of it;
under the wider scope such a module produced a failure that reported nothing
about the service. The scope also now matches the static-analysis gate, which
has always been `bandit -r backend/app`.

**What the pre-filter cannot see.** A literal search matches text, so each of
the following would pass it while making an accepted advisory reachable:

| Evasion | Example |
|---|---|
| An import alias | `from starlette.staticfiles import StaticFiles as Assets` |
| A module attribute | `import starlette.staticfiles as sf` then `sf.StaticFiles(...)` |
| A dynamic import | `import_module("click")` |
| A renamed request parameter | `def handler(inbound: Request): return inbound.url` |
| An aliased request type | `from starlette.requests import Request as Inbound` |
| A reassigned request | `held = request` then `held.form()` |
| A different bracket style | `Route (...)` |

*Layer two — the semantic assertion.* `backend/tests/security/test_residual_risk_guards.py`
closes those gaps. It parses the **abstract syntax tree** of every module under
`backend/app` and asserts, per advisory, that no guarded module is imported
under any name or through a dynamic import, that no guarded symbol is imported
under any alias or reached as an attribute, and that no request object has its
reconstructed address, its base address or its form payload read — resolving
request objects through parameter annotations, through aliases of the request
type, through the conventional parameter names, and through one step of
reassignment. Six of its cases exercise the detection against sources that use
each evasion above, so the guard is asserted to be stronger than the pre-filter
rather than assumed to be.

That module runs inside the security suite, which is itself a gate in
`.github/workflows/ci.yml`, so both layers run on every push and every pull
request. Neither layer is a substitute for the other: the pre-filter is a fast
grep with no dependency on the code importing cleanly, and the semantic
assertion is the one that actually follows the language.

**One construct is deliberately outside both layers.** `starlette.routing` is
imported by `backend/app/main.py` for the single symbol `Match`. That symbol is
an enumeration used to test whether a path matches a route; it is not part of
the dispatch surface PYSEC-2026-2280 concerns. The semantic assertion therefore
guards the symbols `Route`, `WebSocketRoute` and `HTTPEndpoint` and permits
`Match` alone from that module, so importing anything else from it fails the
build.

### Keeping the two sets straight

The two pattern sets are different things and are easy to conflate, so the
distinction is stated explicitly:

| | Fourteen-pattern set | Eight-pattern set | Semantic assertion |
|---|---|---|---|
| What it is | The broad reachability **measurement** | Guard 2's textual **pre-filter** | Guard 2's **syntax-tree check** |
| Scope | `backend/` | `backend/app/` | `backend/app/` |
| Patterns | 14 | 8 | 5 modules, 10 symbols, 3 request attributes |
| When it runs | Taken as evidence for this register | On every build | On every build, inside the security suite |
| Includes `TrustedHost` | Yes, as a control probe | No, deliberately | No, deliberately |
| Sees an alias | No | No | Yes |
| Result | Zero for all fourteen on the pre-remediation tree. On the delivered tree, zero for thirteen at `backend/app/`; at `backend/` no count is published, and every match sits under `backend/tests/`, naming a construct to assert its absence | Zero for all eight | No offender for any advisory |

Describing the pre-filter as covering fourteen patterns, or the measurement as
covering eight, would misstate both. The six patterns in the measurement but not
the pre-filter are the form-handling constructs — `UploadFile`, `File(`,
`Form(`, `OAuth2PasswordRequestForm` and `multipart` — which Guard 1 covers at
the package level and the semantic assertion covers at the symbol level, and
`TrustedHost`, which is a control rather than a risk.

### A change these guards have already refused

The `StaticFiles` pattern is not hypothetical. A browser review of the running
service observed that the two documentation viewers load their scripts,
stylesheets and fonts from external content-delivery networks, and would
therefore render unstyled in a deployment whose egress is filtered. The obvious
remedy — vendoring the viewer bundles and serving them from this application —
is **refused**, because it requires mounting a static-file handler, and the
absence of one is this register's named compensating control for
PYSEC-2026-2281. Taking it would reactivate an accepted advisory, fail Guard 2's
pre-filter on pattern 3, and fail the semantic assertion's `StaticFiles` case.

The observation is not dismissed: it is real, and it is bounded rather than
closed. The documentation pages are a developer surface, `DOCUMENTATION_ENABLED`
governs whether they are published at all, and no API response depends on them,
so a filtered-egress deployment loses page styling and nothing else.
`docs/security/DECISION_LOG.md` row 98.3.7 holds the reasoning and the rejected
alternatives. This paragraph exists so that a future round meeting the same
observation finds the refusal recorded beside the control it would break, rather
than discovering the conflict by failing a build.

## Development register: one accepted development advisory

`backend/requirements-dev.txt` declares the test, lint and static-analysis
tooling. Nothing in it is installed into the runtime image: the backend container
installs `backend/requirements.txt` only, and no name in the development manifest
appears there. The advisory below is therefore confined to a developer
workstation or a continuous-integration runner and serves no request.

`pip-audit --strict -r backend/requirements-dev.txt` reports exactly this one, in
one package:

```text
Found 1 known vulnerability in 1 package
Name   Version ID              Fix Versions
------ ------- --------------- ------------
pytest 8.4.2   PYSEC-2026-1845 9.0.3
```

| Advisory | Package @ pin | Unreachable fix | How it enters the development set | Named compensating control |
|---|---|---|---|---|
| PYSEC-2026-1845 | `pytest` 8.4.2 | 9.0.3 | Declared directly as the test framework | The framework runs only when a developer or a runner invokes it against this repository's own test tree. It is declared in no runtime manifest, so it is absent from the deployed image, and it accepts no network input. |

### Evidence that no fix is reachable

The fix version above was measured, not inferred. It was offered to pip under
CPython 3.9.25 with dependency resolution disabled and refused, because its
metadata declares `Requires-Python >=3.10`. Every release of the fixed major was
refused for the same reason:

```bash
pip install --dry-run --no-deps pytest==9.0.3
```

The interpreter pin that refusal rests on is fixed at five sites and is not
advanced by this work; the sites are enumerated once, in
[The runtime pin](#the-runtime-pin). A pin in the development manifest is raised
only when the raised version installs under CPython 3.9, which is re-measurable
with the command above.

### The audit instrument's own tree

Until this round the Development register carried **seven** identifiers rather
than one, and six of them were not this repository's. They arrived through
`pip-audit`, which was declared in `backend/requirements-dev.txt` and therefore
audited when that manifest was: `msgpack` and `filelock` through
`CacheControl[filecache]`, and `requests` with `urllib3` beneath it, required by
both `pip-audit` and `CacheControl`. Auditing a manifest that declares the
auditor reports the auditor's own supply chain as the project's.

The instrument now lives in `backend/requirements-audit.txt`, which is installed
by the gate and audited by nothing. That is a change to what is measured, not a
suppression: the identifiers are not moved to another ignore list, and no
`--ignore-vuln` flag anywhere names one of them. Measured after the change,
`pip-audit --strict -r backend/requirements-dev.txt` reports one advisory in one
package where it reported seven in five.

The six are identified rather than described, because a reviewer checking that
they have not been quietly re-suppressed needs their identifiers. Auditing the
instrument's own manifest attributes each one to the package that carries it:

```text
$ pip-audit --strict -r backend/requirements-audit.txt
Found 6 known vulnerabilities in 4 packages
Name     Version ID              Fix Versions
-------- ------- --------------- ------------
msgpack  1.1.2   PYSEC-2026-3625 1.2.1
filelock 3.19.1  PYSEC-2026-1375 3.20.1
filelock 3.19.1  PYSEC-2026-1374 3.20.3
requests 2.32.5  PYSEC-2026-2275 2.33.0
urllib3  2.6.3   PYSEC-2026-142  2.7.0
urllib3  2.6.3   PYSEC-2026-141  2.7.0
```

Six is the whole of the difference: the development manifest reported seven
before and one after, and this manifest reports exactly the six that separate
those figures. No advisory was lost between the two measurements, and `pytest`
PYSEC-2026-1845 is absent here because it never belonged to the instrument.
`backend/tests/security/test_release_automation_contract.py` pins these six as
`WITHDRAWN_DEVELOPMENT_SUPPRESSIONS` and fails if any is named on an ignore list
in either workflow again.

What bounds the instrument's own exposure:

1. **It is not in any image.** `pip-audit` is named in neither
   `backend/requirements.txt` nor `backend/requirements-dev.txt`, and
   `infrastructure/docker/Dockerfile.backend` installs the runtime manifest
   alone. No deployed process contains it or anything beneath it.
2. **It runs once, on input it fetched itself.** The advisories concern an
   on-disk HTTP response cache, a lock file in the runner's cache directory, and
   the HTTP client the scanner uses to reach the advisory service. All three are
   exercised only by the scanner's own invocation against a manifest in this
   repository. None reads a request, and none reads attacker-supplied input.
3. **The two packages with runtime history stay out of the runtime graph.**
   `requests` and `urllib3` were removed from `backend/requirements.txt`
   deliberately, and the runtime audit suppresses neither identifier, so it fails
   if either returns. That property is unchanged by this move and is what makes
   the move safe: it does not launder a runtime dependency into a tooling
   manifest.
4. **The boundary is asserted rather than trusted.**
   `backend/tests/security/test_release_automation_contract.py` asserts that each
   audit invocation suppresses exactly the set registered here, so a suppression
   added to a workflow without a register entry fails the build, and a register
   entry with no suppression fails the same test.

The alternatives weighed — replacing the instrument, leaving the six accepted,
and advancing the interpreter — are recorded in
[`docs/security/DECISION_LOG.md`](DECISION_LOG.md) rather than here.

### One identifier, counted once

The Runtime and Development registers are disjoint. No identifier appears in both
audit invocations, and nothing in this register counts an identifier twice.

PYSEC-2026-2275, PYSEC-2026-142 and PYSEC-2026-141 still appear once each in this
file, under [Eliminated by package removal](#eliminated-by-package-removal--4),
because `requests` and `urllib3` left the **runtime** manifest and that genuinely
closed them there: the runtime audit suppresses neither, and would fail if either
reappeared. They are no longer accepted anywhere, because the manifest that
brought them back onto the audited surface is no longer audited.

### The total-suppression accounting

| Line | Count |
|---|---|
| Runtime register entries | 7 |
| Development register entries | 1 |
| **Identifiers suppressed across both audit invocations** | **8** |
| Distinct identifiers among those eight | 8 |
| Identifiers suppressed anywhere in continuous integration but absent from this file | **0** |

The fourth line is worth its own sentence: the two registers are disjoint, so the
eight suppressions are eight distinct advisories rather than a set with overlap.
The fifth line is the property the audit gate's comment asserts, and the one a
reviewer should re-check after any change to either manifest.

## Dispositions that are not residual

Nineteen advisories were present before this work. **Thirteen were closed and six
were accepted.** The seventh accepted advisory was never among the nineteen. This
section records the mechanism behind each disposition, and
[the ledger](#the-one-to-one-ledger) then accounts for all nineteen one by one, so
the headline reduction can be checked rather than taken on trust.

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
manifest, which is what these figures measure. Both are still installed on the
machine that runs the audit, because the audit instrument requires them — but
that instrument's manifest is not audited, so their three advisories are reported
nowhere and suppressed nowhere. They are closed here and accepted in neither
register, as
[The audit instrument's own tree](#the-audit-instruments-own-tree) records.
Nothing in the deployed image installs them, which is what makes their removal
effective for the runtime figures.

### Eliminated by omission — 6

| Advisories | Package omitted | Evidence for the omission |
|---|---|---|
| PYSEC-2026-1852, PYSEC-2026-3036, PYSEC-2026-3037, PYSEC-2026-3038, PYSEC-2026-3039, PYSEC-2026-3040 | `python-multipart` | Never imported anywhere in the service |

### Accepted as residual — 7, of which 6 come from the nineteen

Five in `starlette`, one in `python-dotenv` and one in `click`, all of them in the
runtime manifest and all of them the subject of the
[Runtime register](#runtime-register-seven-accepted-runtime-advisories). The
development manifest's one is not part of this disposition, because it was
never part of the 19 this section accounts for.

Six of those seven were in the pre-work audit: the five in `starlette` and the one
in `click`. **The seventh, PYSEC-2026-2270 in `python-dotenv`, was not**, and the
reason is a reclassification rather than a new exposure. The pre-work audit read a
dependency set reconstructed from `import` statements, because the repository had
no manifest at all. `python-dotenv` appears in no `import` statement — it is
required indirectly, because the settings module declares `env_file` and the
settings framework refuses to construct without the package once that option is
set. So the package was **an undeclared runtime requirement that the audit could
not see**, and its advisory was already present in the running environment before
this work began. Declaring the package made an existing advisory visible; it did
not introduce one. [`python-dotenv` was already a runtime
requirement](#python-dotenv-was-already-a-runtime-requirement) records the
measurement behind that.

This is the only reclassification in the accounting, and it is the only reason the
before-count and the disposition-count differ.

### The one-to-one ledger

Every advisory in the pre-work audit appears exactly once below. The final column
is its disposition, and the four disposition totals are the ones the sections
above record.

| # | Advisory | Package @ pre-work version | Disposition |
|---|---|---|---|
| 1 | PYSEC-2024-38 | `fastapi` 0.99.1 | Closed — fixed by upgrade to 0.125.0 |
| 2 | PYSEC-2026-1943 | `starlette` 0.27.0 | Closed — fixed by upgrade to 0.49.3 |
| 3 | PYSEC-2026-1941 | `starlette` 0.27.0 | Closed — fixed by upgrade to 0.49.3 |
| 4 | PYSEC-2026-2275 | `requests` 2.32.5 | Closed — package removed from the runtime manifest |
| 5 | PYSEC-2026-142 | `urllib3` 2.6.3 | Closed — package removed with its parent |
| 6 | PYSEC-2026-141 | `urllib3` 2.6.3 | Closed — package removed with its parent |
| 7 | PYSEC-2026-1325 | `ecdsa` 0.19.2 | Closed — package removed with its parent `python-jose` |
| 8 | PYSEC-2026-1852 | `python-multipart` 0.0.20 | Closed — package omitted from the manifest |
| 9 | PYSEC-2026-3036 | `python-multipart` 0.0.20 | Closed — package omitted from the manifest |
| 10 | PYSEC-2026-3037 | `python-multipart` 0.0.20 | Closed — package omitted from the manifest |
| 11 | PYSEC-2026-3038 | `python-multipart` 0.0.20 | Closed — package omitted from the manifest |
| 12 | PYSEC-2026-3039 | `python-multipart` 0.0.20 | Closed — package omitted from the manifest |
| 13 | PYSEC-2026-3040 | `python-multipart` 0.0.20 | Closed — package omitted from the manifest |
| 14 | PYSEC-2026-161 | `starlette` 0.27.0 | **Accepted** — fix 1.0.1 unreachable |
| 15 | PYSEC-2026-248 | `starlette` 0.27.0 | **Accepted** — fix 1.3.0 unreachable |
| 16 | PYSEC-2026-249 | `starlette` 0.27.0 | **Accepted** — fix 1.3.1 unreachable |
| 17 | PYSEC-2026-2280 | `starlette` 0.27.0 | **Accepted** — fix 1.1.0 unreachable |
| 18 | PYSEC-2026-2281 | `starlette` 0.27.0 | **Accepted** — fix 1.1.0 unreachable |
| 19 | PYSEC-2026-2132 | `click` 8.1.8 | **Accepted** — fix 8.3.3 unreachable |

And the one entry that is not in the nineteen, listed separately so no subtotal
absorbs it:

| # | Advisory | Package @ delivered pin | Disposition |
|---|---|---|---|
| — | PYSEC-2026-2270 | `python-dotenv` 1.2.1 | **Accepted** — pre-existing but undeclared before this work, so outside the pre-work count; fix 1.2.2 unreachable |

### The arithmetic

Every subtotal now reconciles in both directions.

| Quantity | Figure | How it is composed |
|---|---|---|
| Advisories before | **19** across 7 packages | Ledger rows 1-19 |
| Closed | **13** | 3 fixed by upgrade + 4 by package removal + 6 by omission — ledger rows 1-13 |
| Accepted, from the nineteen | **6** | Ledger rows 14-19 |
| Accepted, reclassified in | **1** | PYSEC-2026-2270, pre-existing and undeclared |
| Advisories after | **7** across 3 packages | 6 + 1 |
| Reduction | **63%** | (19 − 7) ÷ 19 = 63.2% |

The two checks that matter: `13 + 6 = 19`, so every pre-work advisory is
accounted for exactly once; and `6 + 1 = 7`, which is the count the delivered
audit reports. Both figures are reproducible with the commands in
[Reproducing these measurements](#reproducing-these-measurements).

### The development-manifest advisory

Counted separately, never added to the figures above, and listed here because
this register is the index of every accepted advisory. The compensating-control
argument is stated in full in the
[Development register](#development-register-one-accepted-development-advisory),
and inventoried beside the pins it governs in `backend/requirements-dev.txt`.

| Advisory | Package @ pin | Unreachable fix | Route into the graph |
|---|---|---|---|
| PYSEC-2026-1845 | `pytest` 8.4.2 | 9.0.3 | The test framework itself |

No identifier in this register appears in the runtime ledger above, so nothing is
double counted. The three that did — PYSEC-2026-2275, PYSEC-2026-142 and
PYSEC-2026-141 — reached the development surface only through `pip-audit`, and
that instrument's manifest is no longer audited, so they are now closed in the
runtime ledger and accepted nowhere. `requests` and `urllib3` are absent from the
deployed image; the runtime HTTP client is `httpx`.

The one identifier declares `Requires-Python >=3.10` at its fix version, so the
interpreter ceiling applies to this set exactly as it does to the runtime set.

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
at all**; the eight advisories recorded here each have a published fix that is
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

As the workflow stood at the baseline of this work, its `Run Flake8` step ran
`flake8 .` — and nothing anywhere in the workflow ever installed `flake8`. The
only Python installation step in the file installed a requirements manifest that
did not exist in the repository at all. (No line number is quoted here on
purpose: the state being described is the baseline, and a live line reference
would send a reader to whatever occupies that line in the current file.)

The point is not the broken step; it is what the broken step reveals. The tooling
relied upon to verify this codebase was as uninventoried as the codebase's own
dependencies, which is the same class of gap as the missing manifest recorded as
finding INFRA-5. A register of accepted risk depends on its measurements being
reproducible, so the fact that a verification command could sit in the pipeline
indefinitely without its tool ever being installed is directly relevant to how
much weight an unmeasured claim should carry. Every claim in this register is
measured for that reason, and `flake8` is now declared in the development
manifest.

## Development-only accepted advisories

**One** advisory is accepted in `backend/requirements-dev.txt`, and it is
registered in one place rather than two: the
[Development register](#development-register-one-accepted-development-advisory)
carries the identifier, the unreachable fix, the measurement that establishes it
unreachable and the named compensating control, and
`backend/requirements-dev.txt`'s own header inventories it beside the pin it
attaches to. This section previously repeated that table; the repetition was a
second place to keep in agreement and is now a pointer.

| # | Advisory | Package and pin | Fix version | Reached through |
|---|---|---|---|---|
| 1 | PYSEC-2026-1845 | `pytest` 8.4.2 | 9.0.3 | the test framework itself |

**Six advisories that this section previously listed are no longer accepted
anywhere.** They were `pip-audit`'s own dependency tree — `msgpack` and
`filelock` through `CacheControl[filecache]`, and `requests` with `urllib3`
beneath it — reported because the manifest declaring the instrument was the
manifest being audited. The instrument now lives in
`backend/requirements-audit.txt`, which no audit reads, so those six are neither
reported nor suppressed. They are not moved to another ignore list; no
`--ignore-vuln` flag in either workflow names one of them.
[The audit instrument's own tree](#the-audit-instruments-own-tree) records the
measurement, what bounds the instrument's exposure and where the alternatives are
argued.

**The two audited sets remain audited and gated separately.** The runtime audit
is what the seven entries in
[the runtime register](#runtime-register-seven-accepted-runtime-advisories)
belong to, so a development-only advisory can never be mistaken for a runtime
one.

## Findings outside this register

This remediation additionally surfaced findings outside the stated scope. They are
**flagged and awaiting confirmation or an operator action, not fixed**, and none of
them is a dependency advisory. They therefore **do not enter any count in this
register**, which concerns dependency advisories in the runtime manifest only. They
are published as an itemised inventory rather than as a count in
[`docs/security/DECISION_LOG.md`](DECISION_LOG.md) at §35.1, which supersedes the
bare figure at row 34.6.3 for the reason recorded in row 35.1.2: one item closed
because the tree changed rather than because anything was decided, and four
operator-owned items were added by the infrastructure and release-path round.

Four of those ten are also open items in their own right rather than only
observations awaiting confirmation, because something a reader would expect to
work does not. Those four, and five more of the same kind, are set out in
[Open items that are not dependency advisories](#open-items-that-are-not-dependency-advisories)
below. That section is likewise outside every count here.

## Open items that are not dependency advisories

The seven entries above are dependency advisories, and every count in this
register describes that set alone. This section is a **separate register of nine
open items that are not advisories** — two platform end-of-life dates, a third
that has already passed, three cross-layer contract gaps, an absent delivery
prerequisite, an unverified external provider contract, a schedule that is now
delivered but conditional on that contract, and an operational step that has
deliberately not been executed. They are recorded here because a reader of this
file is looking for what was *not* closed, and answering that question only for
dependency advisories would answer it too narrowly.

**One item was split and half of it closed, in the round that produced this
revision.** O-7 previously bundled two unrelated statements: that no Kubernetes
workload objects existed, and that the frontend build platform was
end-of-life with an undeclared dependency. The first is no longer true of this
tree — the manifests are committed and both release paths apply them — so O-7 now
states only what is still open about the cluster, and the frontend half is
carried on its own as O-9. Nothing was decided to close the first half; the tree
changed.

Each entry states what is open, why this remediation did not close it with the
governing clause of the Agent Action Plan (AAP) named, what an operator must do,
and how the item is detectable. **None is a dependency advisory, so
none enters any count above.** The reasoning behind leaving each open is
logged in [`docs/security/DECISION_LOG.md`](DECISION_LOG.md) §36.6, in the same
way the ten flagged findings above are logged at row 34.6.3. Four are also
carried into
[`../review/CRITICAL_DECISIONS.md`](../review/CRITICAL_DECISIONS.md), which
assigns each to a named reviewer with the checks that reviewer should perform.

**Two of these nine were restated because the delivered tree contradicted them,
and the correction is recorded rather than applied silently.** O-7 claimed that no
Kubernetes workload object exists for a deployment to update and O-8 that nothing
schedules the ingestion task. `infrastructure/kubernetes/` carries twelve manifests
— both Deployments and their Services, both autoscalers, the migration Job, the
administrator-credential Job and `65-ingestion-cronjob.yaml` — and both delivery
paths render and apply them. The Kubernetes half of O-7 is therefore closed by
delivery, and O-8 is restated as an **applied-state unknown**: the schedule exists
as a delivered manifest and whether it runs anywhere is outside what this repository
can establish. Rows 91.3.1 and 91.3.2 of the decision log record both restatements,
and row 91.7.1 is the wording rule that keeps delivered, locally verified and
applied state apart.

**What "open" means for each of the nine. Nine are registered and nine are open;
no item is closed in full by delivery, and each needs an operator, a platform
decision or a provider before it can close.** One *half* of one item is closed by
delivery &mdash; the Kubernetes half of O-7, as the paragraph above records &mdash;
and a closed half leaves the item open. Seven are wholly open. The remaining two are open
in narrower senses than when they were written, and narrower is not closed. O-7:
the workload inventory exists and both release paths apply it, but the first
cluster still needs one apply out of band, and the item's frontend half is
untouched. O-8: the schedule ships as a delivered manifest, no evidence here shows
it applied anywhere, and an operator must decide not to enable it until O-9 is
closed. **An earlier revision of this register stated the count as "eight
registered, seven open", which was true of an eight-row register before &sect;93.7
carried O-9 on its own line and is true of no revision since.** Row 96.3.1 of
[`docs/security/DECISION_LOG.md`](DECISION_LOG.md) records the correction, and the
figure a reader should quote is **nine**.

| # | Open item | Kind | Why this remediation did not close it | Decision log |
|---|-----------|------|---------------------------------------|--------------|
| O-1 | The exposed database credential and service-account key are **not rotated by this work**, and a credential-bearing `DATABASE_URL` stays reachable in this repository's history. Whether an operator has since rotated them, and whether the exposed values still authenticate, are issuer-side facts nothing here can establish | Operational, irreversible | AAP §0.10.3 sequences rotation **last**, after every other change is verified, because it cannot be rolled back. It needs provider consoles and a change window | 36.6.6, and 91.7.1 for the wording |
| O-2 | CPython 3.9 is end-of-life and stays pinned at five sites | Platform end-of-life | AAP §0.1.2 makes the pin a hard constraint, names the five sites, and directs that a fix needing a newer interpreter be documented as residual risk rather than taken | 36.6.1 |
| O-3 | The Cloud Function declares the `python39` runtime, which the provider has decommissioned | Platform end-of-life, **blocking** | AAP §0.1.2, the same hard pin as O-2 — the runtime identifier is one of the five pin sites it names | 36.6.1 |
| O-4 | The provisioned database is PostgreSQL 13, which is past end of life | Platform end-of-life | AAP §0.9.2 records it as held for confirmation. A major upgrade is a data-migration event no gate here covers | 36.6.2 |
| O-5 | The browser client posts to a login path this backend does not serve and reads fields it does not return | Cross-layer contract | AAP §0.9.2 places `frontend/src/**` out of scope and names this reported rather than fixed; AAP §0.1.2 freezes the login response shape, so the backend cannot move either | 36.6.3 |
| O-6 | The client drives the provider's subscription product while the backend implements orders, and the two name subscription fields differently | Cross-layer contract | AAP §0.9.2 and §0.1.2, the same pair as O-5: the client side is out of scope and the backend's shape is frozen | 36.6.3 |
| O-7 | The workload objects **are** versioned here now and both release paths apply them, but each path's preflight requires the two Deployments to exist before it changes anything, so the very first cluster still needs a one-time apply out of band; and the frontend builds on an end-of-life Node major with one undeclared dependency | Delivery prerequisite, narrowed | AAP §0.6.1 is an exhaustive 68-entry mapping holding no Kubernetes manifest, which is why the inventory arrived later than the plan; AAP §0.9.2 places `frontend/package.json` out of scope and holds the Node pin for confirmation | 36.2.4, 36.6.4, 82.28, 88.1, 92.9 |
| O-8 | The ingestion schedule is delivered as a Kubernetes CronJob, and an operator must not enable it until O-9 is closed, because an unverified adapter on a schedule fails every hour rather than once | Delivered, conditional | AAP §0.9.2 excludes feature additions unrelated to security, so the schedule exists only because the runtime it replaced was decommissioned; the provider contract it calls stays out of scope under the same clause | 36.6.5, 82.2, 88.2, 92.1, 92.7 |
| O-9 | The listing provider's request shape, parameter names and response fields are a declaration of this repository rather than a contract verified against a provider, so the adapter may not work against a real one | External contract | AAP §0.6.1.2 authorises exactly three security changes to this adapter — the credential into a header, an explicit timeout and the redacting logger — and AAP §0.9.2 excludes feature additions and directs that findings outside scope be reported rather than fixed | 80.5.3, 92.1 |

### O-1 — the rotation and the history rewrite

`infrastructure/docker/docker-compose.yml` carried a credential-bearing
`DATABASE_URL` and referenced a mounted service-account key. Both are gone from
the current tree, `.gitignore` and `.dockerignore` prevent reintroduction, and
Secret Manager resources are provisioned to hold them properly. **None of that
revokes the exposed values.** A credential is compromised the moment it is
committed, and every clone that already exists still carries the history holding
it.

**What an operator must do.** Work through
[`CREDENTIAL_ROTATION.md`](CREDENTIAL_ROTATION.md) in the order it sets out:
revoke, then rotate, then delete from history, then review the access that
preceded the exposure. The order is load-bearing rather than stylistic —
rewriting history before revoking leaves a live credential valid inside every
existing clone, so a rewrite done first is worse than no rewrite at all.

**How it is detectable.** No document here claims either step is done, and
`backend/tests/security/test_documentation_citations.py::test_no_document_claims_the_credential_rotation_is_complete`
asserts that across five documents: a sentence claiming rotation must sit inside
a window marking it required, outstanding or conditional. An edit that quietly
promotes the runbook into a completion claim fails that case.

### O-2 and O-3 — the interpreter, and the runtime that is already gone

CPython 3.9 is past end of life and receives no further security fixes. It is
pinned at five sites, and the pin is a property of the code as well as the
configuration: `backend/app/tasks/listing_updater.py:329` uses
`@asyncio.coroutine`, removed in Python 3.11, so the ingestion task would not run
on a newer interpreter even if every configuration pin were raised.
[`TRACEABILITY_MATRIX.md`](TRACEABILITY_MATRIX.md) carries all five sites, at
their baseline line numbers: that file states its own convention, which is that
every number in it resolves against revision `a26f7fb` rather than against the
delivered tree. The delivered numbers are the ones quoted here and in
[`../review/CRITICAL_DECISIONS.md`](../review/CRITICAL_DECISIONS.md), and
`test_deployment_contract.py` reads each of them back from the file it names.

**O-3 is the sharper half and is stated separately because its consequence is
present rather than future.** The Cloud Function is declared with the `python39`
runtime identifier, which the provider has decommissioned. The published runtime
lifecycle is explicit about what that means operationally: after the decommission
date a workload using that runtime can no longer be created or updated, a
supported runtime must be chosen instead, and workloads still using a
decommissioned runtime may be disabled. The review that raised this recorded the
decommission date as 5 April 2026, which has passed. **The Cloud Function
declared in `infrastructure/terraform/main.tf` and deployed by
`scripts/deploy.sh` therefore cannot be created or updated as configured.**

Everything else in this delivery is unaffected. The backend service runs the
pinned interpreter from its own container image, which carries no such lifecycle
gate, so this is a single-component blocker rather than a system-wide one.

**Why it was not closed.** AAP §0.1.2 states the pin as a hard constraint, names
the five sites, and gives the treatment directly: where the only fix needs Python
3.10 or later, document accepted residual risk with a compensating control rather
than advancing the interpreter. Raising the function's runtime identifier alone
was considered and refused, because it would split the deployment across two
interpreters so that the function and the service were no longer verified against
the same one.

**What an operator must do.** Treat the interpreter migration as its own piece of
work and expect it to be the largest item remaining. Its first step is the
decorator at `backend/app/tasks/listing_updater.py:329`; its second is the four
configuration sites. It invalidates this whole register, because all seven
accepted advisories become installable at once — see
[Maintaining this register](#maintaining-this-register), event 3.

**How it is detectable.** `test_documentation_citations.py` asserts each of the
five sites still carries its construct at the cited line, so the pin cannot move
without the documentation moving with it. The function's runtime is asserted from
both files by
`test_pipeline_contract.py::test_the_function_runtime_pin_is_intact` and
`::test_the_deployment_script_deploys_no_public_function`, so a change there is
deliberate rather than incidental.

### O-4 — the database major version

`infrastructure/terraform/main.tf` provisions PostgreSQL 13 and
`infrastructure/docker/docker-compose.yml` runs the matching image. That major is
past end of life and will receive no further security patches.

Raising the Terraform `database_version` is a one-line edit and is not a one-line
change. The verification environment installs PostgreSQL 13 precisely because
Compose and Terraform pin it, so moving the major moves the pin out from under
the environment in which every gate in this repository was measured — and a
database major upgrade is a data-migration event that no test here covers. AAP
§0.9.2 records the finding as held for confirmation.

**What an operator must do.** Plan the upgrade with a data migration and a tested
rollback, and move the Compose image, the Terraform `database_version` and the
verification environment together rather than one at a time.

### O-5 and O-6 — the browser-client contract

Three distinct mismatches. The client posts to a login path this backend does not
serve and reads response fields it does not return. It drives the payment
provider's subscription product while this backend implements the orders product.
And its subscription model names fields in a different convention from the
backend's response.

**The gap cannot be closed from either side within this scope, which is exactly
why it is reported rather than fixed.** AAP §0.9.2 places everything under
`frontend/src/**` out of scope and names two of the three explicitly as reported
rather than fixed. AAP §0.1.2 freezes the `{access_token, token_type}` login
response shape and all eight route paths, so changing the backend to match the
client would break the interface the plan exists to protect. The four client
files were read to constrain the design and are listed as REFERENCE paths in
[`TRACEABILITY_MATRIX.md`](TRACEABILITY_MATRIX.md) §2.7.

**Operational consequence, stated plainly.** The browser client cannot
authenticate against this backend and cannot complete a payment through it. This
is the largest unclosed gap in the delivery. It is not a security weakness — the
backend refuses the client's requests rather than mishandling them — but it does
mean the delivered system is not end-to-end functional through the browser, and
no artefact here should be read as implying otherwise.

**What an operator must do.** Authorize a frontend change, then align the client
to the backend rather than the reverse, because the backend's shape is the frozen
one.

### O-7 — the first cluster apply, and the frontend build's two prerequisites

**One half of this item is closed by a change of state, and it is recorded that
way rather than removed.** An earlier revision of this register said that no
Kubernetes workload objects existed for the deployment to update and that
nothing in this repository created them. That is no longer true of this tree.
`infrastructure/kubernetes/` carries the whole inventory — namespace, service
accounts, settings map, two secret deliveries, the backend and frontend
Deployments and Services, both autoscalers, the schema-migration Job, the
ingestion CronJob and the administrator-credential Job.
`scripts/render_kubernetes_manifests.sh` is the one substitution pass over them,
and both `.github/workflows/cd.yml` and `scripts/deploy.sh` invoke it and apply
its output, so the manifests that are validated are the manifests that are
applied. `infrastructure/k8s/README.md` records the consolidation that produced
that single inventory. Nothing was decided to close this half; the tree changed.

**What remains open.** The objects are declared here; they are not present in a
cluster. `scripts/deploy.sh` asserts that the `backend` and `frontend`
Deployments already exist, and that each declares a container of its own name,
before it changes anything — it publishes into an inventory that exists and
creates no workload. So the first application of the prerequisite manifests is
an operator action: no release path in this repository can reach a cluster,
because the control plane has no public endpoint and this repository has no
credential for one. A release run before that first application stops and names
the missing Deployment rather than creating it implicitly.

AAP §0.6.1 contains no step that applies a manifest to a cluster, and a release
that created its own workloads would silently define the running specification
from whichever path ran last. Row 36.2.4 records the alternatives.
`test_pipeline_contract.py::test_every_mutated_workload_is_confirmed_to_exist_first`
holds the assertion in place, and
`.github/scripts/check_manifest_settings_contract.py` checks the committed
manifests against the settings contract in the `infrastructure` job.

**The second half of this item is untouched, and is a frontend concern rather than
a backend one.** The frontend continuous-integration job builds on an end-of-life Node
major, and `frontend/package.json` omits a dependency the source imports, so a clean
install resolves it only by accident of the tree it lands in. Neither is a defect in
the backend this remediation hardened, and neither is fixable inside its boundary: AAP
§0.9.2 places the frontend source out of scope, holds the Node pin for confirmation,
and directs that a finding outside scope be reported rather than fixed. Both are
therefore reported here and carried in this item's row rather than closed, which is why
this entry stays open after its cluster half narrowed.

**What an operator must do.** Render the `prerequisites` group with
`scripts/render_kubernetes_manifests.sh` and apply it once, then apply the
`workloads` group, before the first release. Both release paths take over from
there. Separately, and under a frontend authorization this work does not carry,
declare the missing dependency in `frontend/package.json` and raise the Node major.

### O-8 — the ingestion schedule is delivered but not applied

**This entry previously said no production trigger existed. That is no longer
true, and the correction matters more than the entry itself: an operator sent to
solve a scheduling gap that has been closed would not look at the two risks the
delivered schedule actually carries.**

`infrastructure/kubernetes/65-ingestion-cronjob.yaml` runs
`backend.app.tasks.listing_updater.update_listings` once per
`${INGESTION_SCHEDULE}` on the backend image, under the same CSI secret mount and
the same non-root security context as the API. It exists because the managed
`python39` Cloud Function that was supposed to provide the periodic refresh is on
a decommissioned runtime and was deleted; the decision is
[`DECISION_LOG.md`](DECISION_LOG.md) §82.2, and §88.2 records carrying it onto the
surviving manifest inventory. Row 80.6.5 — "do not add a production scheduler" —
is **withdrawn** by row 92.7.

Two risks remain, and neither is the one this entry used to describe.

- **The pass it runs calls an adapter whose contract is unverified.** That is O-9.
  A schedule multiplies an unverified contract by its frequency: hourly, an
  adapter that does not match the provider fails every hour rather than once.
- **The schedule's cadence is an operator input.** `${INGESTION_SCHEDULE}` is a
  required substitution token, so `scripts/render_kubernetes_manifests.sh` refuses
  to render until the operator sets it. There is no default cadence to inherit.

**What was fixed rather than left open.** A failed pass used to exit **0**. Every
provider failure — a transport error, a refused status, an oversized body, a body
that is not decodable, and every response that does not satisfy the adapter's
declared contract — was converted to an empty list, and `update_listings` caught
and swallowed anything raised, so `asyncio.run(update_listings())` completed
successfully and logged `Completed an ingestion pass`. The CronJob's
`backoffLimit: 2` and its failed-job history could therefore never engage, and a
provider outage was indistinguishable from a quiet corpus. `fetch_listings` now
raises `ListingProviderError` carrying a stable `reason`, `update_listings` rolls
back and re-raises, and the process exits non-zero. A provider that answered and
reported no listings is still a completed pass.
`backend/tests/security/test_delivery_pipeline.py::test_the_ingestion_schedule_can_observe_a_failed_pass`
holds both halves of that contract together — the manifest's attempt limit and
failure history, and the task's rollback-then-raise.

**What an operator must do.** Close O-9 before setting `INGESTION_SCHEDULE`, or
accept a schedule whose jobs fail visibly until it is closed — and monitor
failed-job history, which is now the signal it was always supposed to be.

### O-9 — the listing provider's contract is unverified

`backend/app/services/zillow_service.py` declares the request shape, the
parameter names and the response fields it reads. **None of them was verified
against a listing provider.** The adapter is correct against its own declaration
and against its tests, and that is the whole of what can be claimed for it.

This is an open item in its own right, promoted from a note that previously said
it was "not an open item ... recorded here because it conditions O-8". That
framing understated it: a delivered integration whose wire contract has never been
checked against the far side is a gap, not a footnote, and the code review that
prompted this correction was right to say so.

**Why it was not closed here.** AAP §0.6.1.2 enumerates this file's entire
authorised change set — the credential into a request header, an explicit timeout,
and the redacting logger — and AAP §0.9.2 excludes feature additions unrelated to
security and directs that findings outside that scope be reported for confirmation
rather than fixed. Choosing a provider is also not a code decision: Zillow retired
its public Web Services API in September 2021, and its official successor is an
approval-gated RESO Web API requiring a multiple-listing-service membership or an
approved partnership, so there is no self-serve contract to implement and any
substitute is a licensing and product choice an operator owns. Row 92.1 records
the alternatives.

**What is delivered and verified.** The *security* properties of the boundary, all
asserted by tests: the credential travels in a request header and appears in no
URL, query string or log record; every call carries an explicit timeout; the
response body is size-capped before it is read; the listing count is capped; the
postal-code chunk is capped; a destination outside the provider allowlist is
refused without a request being issued; and no search value or credential reaches
a log record or a raised message.

**What changed here to make the gap discoverable rather than silent.** The whole
declared contract is now published as one immutable object,
`DECLARED_PROVIDER_CONTRACT`, naming the method, the credential header, the
postal-code parameter, the response collection key and the per-field source map —
so an operator re-pointing the adapter has one place to look and one place to
change. And a response that does not satisfy that declaration now **fails**,
naming the element that did not match, where it previously read as a corpus with
nothing in it. The first live call against a real provider therefore reports the
difference instead of hiding it.
`backend/tests/test_services.py::TestTheDeclaredListingProviderContract` states in
its own docstring that its payloads encode the declared contract rather than a
verified one, so the provenance is visible in the test that would otherwise be
mistaken for evidence of a working integration.

**What an operator must do.** Identify the provider and obtain its specification
and credentials, then align the five entries of `DECLARED_PROVIDER_CONTRACT` and
`PROVIDER_FIELD_SOURCES` to it and replace the contract fixtures with ones derived
from that specification. Do this before enabling the schedule in O-8.

### Why these nine sit here rather than in the count above

A reader could reasonably ask why this section is not folded into the seven.
Three reasons, and they are the same three that keep every count in this register
describing dependency advisories alone.

- **They are not advisories.** None has a CVE, a PYSEC identifier, a fix version
  or a CVSS vector, so none can be audited, suppressed or re-measured by
  `pip-audit`. Counting them beside the seven would make this register's headline
  figures unreproducible from the command that produced them.
- **They are not all risks in the same sense.** O-5 through O-9 are functional
  gaps rather than security weaknesses: the delivered system refuses or omits
  work rather than performing it unsafely. Presenting them as accepted security
  risk would overstate the exposure while understating the functional shortfall,
  which is the more accurate criticism of this delivery.
- **They have different owners.** The seven above are closed by one interpreter
  migration. These nine are closed by an operator action, a platform upgrade, a
  frontend authorization, a provider agreement and a scheduling decision — five
  pieces of work with five different approvers.

## Workflow toolchain references: closed, and how it was closed

**Current state.** Every action either workflow references is pinned to a full
commit with the release it was published as recorded beside it, and no action is
exempt. `backend/tests/security/test_pipeline_audit_contract.py` asserts both
properties over both workflows with no exemption set, so a tag reference or an
undocumented commit fails the build.

The Terraform binary is pinned with it: the `infrastructure` job passes an exact
`terraform_version` to `hashicorp/setup-terraform`, so the binary that runs
`terraform validate` is the release the configuration is verified with rather
than whichever one the action resolves. That version also clears the 1.11 floor
the ephemeral input variables and write-only secret arguments in
`infrastructure/terraform/main.tf` require. **The configuration itself declares no
`required_version` and no `required_providers`, and no provider lock is tracked**;
that absence is a finding reported for confirmation rather than closed, it is
stated in the configuration's own comment block, and
`docs/security/DECISION_LOG.md` rows 91.1.1 and 96.1.1 own the reasoning. The pin
above therefore rests on the release this repository verifies against, not on a
constraint the configuration states.

| Reference | Commit | Release |
|---|---|---|
| `actions/setup-node` | `249970729cb0ef3589644e2896645e5dc5ba9c38` | v6.5.0 |
| `hashicorp/setup-terraform` | `b9cd54a3c349d3f38e8881555d616ced269862dd` | v3.1.2 |

**Superseded record.** This section previously carried these two references as an
open item, on the stated ground that their commit identifiers were not derivable
in the environment this repository is verified in. That ground was wrong. Both
resolve from `git ls-remote --tags --refs`, and the method was cross-checked
against the `actions/setup-python` pin the `backend` gate already carried, which
it reproduces exactly. The item is closed rather than re-scoped, and the
bounded-exposure argument it rested on is withdrawn with it: neither reference is
tag-pinned any longer, so nothing depends on where those two jobs run.

**Bootstrap installer.** The five jobs that read a manifest install the
bootstrap installer before they do, and it is pinned to one exact version
declared once at workflow scope in `.github/workflows/ci.yml` as `PIP_VERSION`
and read from there by every install. It is inventoried in
`backend/requirements-dev.txt`. It is a toolchain reference rather than a
dependency of the delivered application: it is installed by the gate, is present
in no image and no manifest resolution, and is therefore not audited by either
`pip-audit` invocation. Its pin is what keeps an installer outside both audited
manifests from resolving a new release at the moment the gate runs.

## Maintaining this register

An accepted risk is only accepted for as long as its compensating control holds.
Five events invalidate an entry above. The first two are detected automatically;
the last three are not, and are the reason this register names a maintenance
obligation rather than declaring the matter settled:

1. **A guard fails.** Guard 1 failing means `python-multipart` has returned and
   the PYSEC-2026-249 control has lapsed. Either layer of Guard 2 failing means a
   construct that makes an accepted advisory reachable has entered
   `backend/app/`. Neither should be suppressed; each should be treated as the
   acceptance being withdrawn. A failure in the semantic layer names the advisory
   it belongs to and the module it was found in, so the withdrawn entry is
   identifiable from the failure alone.
2. **A ceiling moves.** If a fix version is republished with metadata that admits
   CPython 3.9, that interpreter barrier falls for the corresponding entry. The
   ceilings are re-measurable with the commands in
   [Reproducing these measurements](#reproducing-these-measurements). For the five
   `starlette` entries, Constraint 2 still has to be cleared separately.
3. **The runtime pin changes.** Every entry here is conditional on CPython 3.9.
   If the pin is ever revisited — a decision recorded at row 1.9 of
   [`docs/security/DECISION_LOG.md`](DECISION_LOG.md), not here — this register
   must be re-derived from a fresh audit rather than amended. Note what that
   re-derivation would find: `python-dotenv` 1.2.2 and `click` 8.3.3 become
   installable, closing **two** entries, while the five `starlette` entries stay
   open until the FastAPI and Pydantic constraint in
   [Constraint 2](#constraint-2--the-framework-resolver-which-applies-to-the-five-in-starlette)
   is also resolved.
4. **A reachability precondition changes outside the guarded set.** The four
   assumptions in [What the evidence establishes, and what it does
   not](#what-the-evidence-establishes-and-what-it-does-not) are not all
   machine-checked. A move to a Windows host, a form-handling construct outside
   Guard 2's eight patterns, or a transitive resolution change beyond
   `python-multipart` would each invalidate an entry with no build failing.
   Re-run the fourteen-pattern measurement when any of those changes.
5. **An advisory description is amended.** Each control is written against the
   defect as published. A widened description may not be answered by the control
   chosen for the narrower one. This register has already been corrected once on
   that account.
