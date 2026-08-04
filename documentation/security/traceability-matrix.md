# Security Remediation Traceability Matrix

This matrix maps each of the twelve security findings to the files that carry its control, and each
file back to the findings it closes. A reviewer can therefore confirm coverage without reconstructing
intent from a diff.

Findings are identified `SEC-01` through `SEC-12`, the numbering supplied with the brief. Severity
ratings are the reporter's. Weakness classifications are analysis rather than database lookups: none
of the twelve is a published vulnerability in this codebase, so none carries a CVE identifier.

Paths are relative to the repository root. Where a sentence describes a defect, its line reference
locates the code as it stood before the change, and a few of those lines have since moved.

**What lives elsewhere.** [`decision-log.md`](decision-log.md) is the single source of truth for
**why** each choice was made, and it holds the alternatives weighed and the risks accepted.
[`SECURITY.md`](../../SECURITY.md) carries operational secret handling, the verification commands, the
deferred follow-ons and the residual-risk register. This file records **what closes what, and where**.
Neither companion document is restated here.

## The scope judgment

Rule 1 conditions this artifact on a class of work: "For migrations or refactors, include a
bidirectional traceability matrix mapping source constructs to target implementations — 100%
coverage, no gaps." Two parts of this work are migrations: SEC-06 moves the session token from browser
storage to an `HttpOnly` cookie, and `backend/requirements.txt` moves an implicit, unpinned dependency
set into an explicit, pinned one.

**This matrix covers all twelve findings in both directions, not those two parts alone.** Section 3.1
carries the measured coverage figures. [`decision-log.md`](decision-log.md) `DL-395` carries the
decision behind the wider scope and behind stating the coverage as measured.

## How to read it

- **Section 1** runs finding to control to file. Every mechanism is stated once, there.
- **Section 2** runs file to control to finding, grouped by directory. Cells name the control and
  point back to section 1 rather than repeating it.
- **Section 3** reconciles the two directions, and states where delivery departed from the plan.
- **Section 4** carries the measured evidence: what each gate read before the work and after it.
- **Section 5** lists the design intent in the sibling specifications that this work does and does
  not deliver.

---

## 1. Direction A — finding to control to file

Thirteen rows: the twelve findings, plus the dependency-integrity prerequisite that had to be closed
before any of them could be tested. Four rows are labelled **Partial**, with the remaining gap named;
[`SECURITY.md`](../../SECURITY.md) section 3.2 carries the operator-facing detail on all four.

| Finding | Weakness and severity | Control that closes it | Files carrying the control |
| --- | --- | --- | --- |
| **SEC-01** | Hardcoded credentials in a tracked file. CWE-798, CWE-540. A07:2021, secondary A05:2021. Critical | Environment indirection with no inline default replaces the literal at `docker-compose.yml:30` in the pre-fix tree, so a missing value fails loudly instead of falling back. The Compose variable name, at `:31` in that tree, changes from `JWT_SECRET` to `SECRET_KEY`, the name the backend settings class actually reads. New exclusion and template files keep a generated secret file uncommittable, and the development script generates credentials instead of emitting them and publishes the result with a no-clobber link rather than a move over whatever stands there. The Compose definition carries the whole no-default settings contract in the fail-closed `${VAR:?message}` form, so an unset value stops the container start with a named message instead of interpolating to empty. The config-guard module asserts this finding's shipped text directly: the credential-scan expressions and both gate stages, the generated-file mode guards, the publish primitive against a destination planted in three forms, and the order `main` runs the provisioning steps in | `.gitignore`, `.env.example`, `infrastructure/docker/docker-compose.yml`, `scripts/setup_dev_environment.sh`, `.github/workflows/ci.yml`, `backend/tests/security/test_config_guards.py` |
| **SEC-02** | Broken authentication through identity mismatch. CWE-287, CWE-863. A01:2021. High | The subject claim is minted as `str(user.id)` and coerced back with `int()` inside a guard that answers 401, so the claim and the queried column share a type. The bare 404 at `security.py:49-50` in the pre-fix tree becomes a 401 carrying `WWW-Authenticate: Bearer`, at `:86-90` as shipped, an `iat` claim joins the existing `exp`, and the outbound user model retypes `id` from `str` to `int` and drops its password-hash field | `backend/app/core/security.py`, `backend/app/api/endpoints/auth.py`, `backend/app/schema/user.py`, `backend/tests/security/test_auth_identity.py` |
| **SEC-03** | Permissive cross-origin policy with credentials. CWE-942, CWE-346. A05:2021. High | `ALLOWED_ORIGINS` becomes a required list whose validator rejects an empty list, `"*"`, the literal `"null"` and any entry that is not a full origin. Matching is exact string equality, with no reflection and no regular expression, and the two middleware wildcards give way to explicit method and header lists. A misconfigured allow-list stops startup | `backend/app/core/config.py`, `backend/app/main.py`, `.env.example`, `backend/tests/security/test_cors_policy.py` |
| **SEC-04** | Weak password requirements. CWE-521. A07:2021. Medium | A validator on the new `UserCreate` model mirrors the client character set at `validators.ts:18-32`, twelve characters with an upper, a lower, a digit and a special character, and adds a hard maximum at the 72-byte bcrypt ceiling. The ceiling is measured, not nominal: at the pinned `bcrypt==4.3.0` a 100-character password is accepted silently. `DL-226` carries the byte-versus-character bound | `backend/app/schema/user.py`, `backend/app/api/endpoints/auth.py`, `backend/tests/security/test_password_policy.py` |
| **SEC-05** | Improper input validation and mass assignment. CWE-20, CWE-915. A03:2021, secondary A04:2021. High | `UserCreate`, `UserLogin`, `FilterCreate` and `ListingCreate` arrive alongside a new `subscription.py` module, and every create model sets `extra = "forbid"` so an unknown key is rejected rather than absorbed. That single setting is the mass-assignment control for the expansion at `listings.py:21`, which passes the request body straight into a mapped constructor. A model closes nothing until a route binds it, so the two updated write endpoints are claimants in their own right: `auth.py:189` and `:233` bind `UserCreate` and `UserLogin`, and `listings.py:18` binds `ListingCreate` ahead of that expansion. `filters.py:17` bound `FilterCreate` before this work and supplies the reference pattern; `filters.py:25-37` is a delivered control in its own right, copying the validated allow-list onto mapped `Criteria` children and keeping `created_at` server-owned. Type validation alone is not the whole boundary: each declared float is also checked for finiteness, so `NaN`, `Infinity` and a literal no float can hold are refused at the boundary. `DL-335` carries the scope of that check. On the client side the service module maps the filter form's own value onto this contract, so the request that reaches the allow-list is the one the form produces, and the listing card gates an outbound link on an `http` or `https` scheme so a stored `javascript:` value renders as inert text rather than reaching an `href`; `DL-430` carries that seam. One claimant is an authority rather than a control: `subscriptions.py:4` names the models the created `schema/subscription.py` had to export, and its section 2 row records the same relation | `backend/app/schema/user.py`, `backend/app/schema/filter.py`, `backend/app/schema/listing.py`, `backend/app/schema/subscription.py`, `backend/app/api/endpoints/auth.py`, `backend/app/api/endpoints/listings.py`, `backend/app/api/endpoints/filters.py`, `backend/app/api/endpoints/subscriptions.py`, `frontend/src/services/api.ts`, `frontend/src/schema/filter.ts`, `frontend/src/schema/listing.ts`, `frontend/src/components/ListingCard.tsx`, `backend/tests/security/test_input_validation.py` |
| **SEC-06** | Session token in browser-accessible storage. CWE-522, CWE-1004. A07:2021. Medium | The register and login routes set an `HttpOnly`, `Secure`, `SameSite=Strict` cookie while leaving the JSON body untouched, and the guard reads that cookie before the bearer header, so non-browser clients still work. `POST /auth/logout` clears it server-side, which `DL-255` records as an addition to the route set. The frontend drops browser storage, corrects its request path to `/auth/login`, exports `API_BASE_URL` and sends credentials; axios is pinned exactly and the cross-site-token option is deliberately left unset. A pipeline gate scans `frontend/` for browser storage on every run, so the removal cannot be undone silently. The client also declares no path the application does not serve: the call to an unmounted profile route is gone, and a case compares every path the client declares against the application's own route table. A second regression module asserts the guard's cookie-first read from the other side: a request carrying no session cookie is refused with 401 before anything reads the body. **Gaps**: browser persistence is removed, but `access_token` stays script-readable in the frozen response body, so `HttpOnly` bounds cookie reads and nothing more. And clearing the cookie ends the browser's session and revokes nothing — a token already copied elsewhere authenticates until it expires, because verification consults no revocation record | `backend/app/core/security.py`, `backend/app/api/endpoints/auth.py`, `backend/app/core/config.py`, `frontend/src/services/auth.ts`, `frontend/src/services/api.ts`, `frontend/package.json`, `.github/workflows/ci.yml`, `backend/tests/security/test_token_storage.py`, `backend/tests/security/test_input_validation.py` |
| **SEC-07** | Unrestricted authentication attempts. CWE-307. A07:2021. Medium. **Partial** | A limiter with in-memory storage applies five attempts per fifteen minutes to `POST /auth/login`, layered with an in-process counter keyed by the **exact stored identity** so a distributed attempt on one account is also bounded. The counter key is the exact value the credential query filters on, so counter identity and database identity are one value; `DL-337` carries the correction from the earlier folded key. Both credential branches perform one fixed-cost password verification, against a per-process random stand-in hash when no row matches, and the equality asserted is hasher invocation count rather than wall-clock duration. `DL-338` carries that branch. Throttled attempts are logged rather than silently dropped. The address layer's key is a deployment property as much as a code one, so the image definition is a claimant here: its command carries `--no-proxy-headers`, which keeps the key on the TCP peer instead of letting `X-Forwarded-For` write it, and `DL-433` carries that posture with the trust boundary it rests on. **Gaps**: total request timing is not proven equal, because the absent branch skips one query (`DL-338`). The throttle state is per-worker and lost on restart, so lockout is neither durable nor multi-replica-safe. And behind a reverse proxy every caller presents the proxy's address, so the address layer then holds one shared key | `backend/app/main.py`, `backend/app/api/endpoints/auth.py`, `backend/app/core/config.py`, `infrastructure/docker/Dockerfile.backend`, `backend/tests/security/test_login_throttle.py`, `backend/tests/security/test_config_guards.py` |
| **SEC-08** | Information exposure through an error message. CWE-209, CWE-497. A05:2021. Medium | Four global handlers replace the placeholder comment that stood at `main.py:35` in the pre-fix tree, sharing one response envelope and a correlation identifier while full diagnostics go to the server log. Uniformity is the requirement, so the SEC-02 normalisation of the 404 into a 401 belongs to this row as well: a differential response is an account-state oracle. `DL-241` carries it. On the log side, a record factory scoped to this application folds every record to one line at creation, before propagation, and every C0 control character and the delete character are translated. `DL-339` and `DL-340` carry the placement and the character set | `backend/app/main.py`, `backend/app/core/security.py`, `backend/tests/security/test_error_handling.py` |
| **SEC-09** | Insecure default initialization of a resource. CWE-1188, CWE-798. A05:2021. High | `PAYPAL_MODE` is restricted to `sandbox` or `live`, and the service reads it from the settings class at `paypal_service.py:75` and `:306`, in place of the hardcoded literal and its manual-edit comment, which stood at `paypal_service.py:11` in the pre-fix tree. A pipeline step asserts that no client-secret pattern appears under `frontend/`; the property already held, so the step converts an accident into an invariant. The charge seam is the second half of this row. A charge authorizes only against a reference the provider confirms for the requested amount, currency and payer, and for a reusable agreement only for the plan the request names. It is recorded in a worker-local ledger that refuses a replay while the digest is retained, and `subscriptions.py:24` binds the requested plan on the call. `DL-332`, `DL-124` and `DL-201` carry these three. **Gap**: the ledger holds 4,096 digests per worker, evicts the oldest past that and is lost on restart, so replay protection is neither durable nor multi-replica-safe | `backend/app/core/config.py`, `backend/app/services/paypal_service.py`, `backend/app/api/endpoints/subscriptions.py`, `.github/workflows/ci.yml`, `backend/tests/security/test_config_guards.py` |
| **SEC-10** | Cleartext transmission to the database. CWE-319. A02:2021. High. **Partial** | The Cloud SQL instance gains `ip_configuration { ssl_mode = "ENCRYPTED_ONLY" }`, and the engine passes an environment-driven `sslmode` through `connect_args` for PostgreSQL URLs only, since SQLite raises `TypeError` on that argument. The control sits at both ends: the instance refuses unencrypted connections, and the engine requests encryption. `DL-245` carries the documented local exception for the Auth Proxy topology. The deprecated `require_ssl` argument is not used. The provider that supplies the encryption argument is part of the control: the configuration bounds it to one major line, and the generated lock is tracked with a directory hash for each of the four platforms an operator or the pipeline installs from. `DL-350` carries the lock decision. **Gap**: `require` encrypts but performs no server-identity check | `infrastructure/terraform/main.tf`, `infrastructure/terraform/.terraform.lock.hcl`, `backend/app/core/config.py`, `backend/app/db/database.py`, `infrastructure/docker/docker-compose.yml`, `.env.example`, `backend/tests/security/test_config_guards.py` |
| **SEC-11** | Execution with unnecessary privileges. CWE-250, CWE-269. A01:2021. Medium. **Partial** | The two halves reach different depths. Locally the single all-privileges account splits into an owner role used for schema work and an application role holding only connect, schema usage and table data rights. Two revokes strip the defaults `PUBLIC` holds: `CREATE` on the schema, and `CONNECT` with `TEMPORARY` on the database. The batch then reads the **effective** access lists and raises rather than trusting the statements it just issued, substituting the default list where the stored one is null. `DL-36`, `DL-353` and `DL-354` carry those three. On Cloud SQL, Terraform declares a `google_sql_user` whose password comes from a variable rather than a literal, which separates the account from the instance admin and restricts nothing; the out-of-band statements in `SECURITY.md` section 3.2 are what narrow it, and `DL-293` carries the declaration. **Gaps**: the cloud account stays elevated until an operator runs the statements `SECURITY.md` section 3.2 carries, schema `USAGE` is deliberately left with `PUBLIC`, and nothing here delivers row-level security | `scripts/setup_dev_environment.sh`, `infrastructure/terraform/main.tf`, `infrastructure/terraform/variables.tf`, `infrastructure/terraform/.terraform.lock.hcl`, `.gitignore`, `SECURITY.md`, `backend/tests/security/test_config_guards.py` |
| **SEC-12** | Insufficiently protected credentials in custody. CWE-522. A05:2021. Medium. **Partial** | Exclusion rules and a template carrying no real secret keep secrets out of version control. Every secret and deployment-specific identifier in that template is an angle-bracket placeholder; the remaining lines document non-secret code defaults and required choices. `SECRET_KEY` gains a `min_length=32` floor grounded in RFC 7518 section 3.2, the three settings that raised `AttributeError` are declared, and a pipeline secret scan enforces the discipline on every run. Provisioning carries the same custody. The setup script generates values instead of emitting literals and creates the file under `umask 077`, per `DL-40` and `DL-181`. Terraform takes the database password from an `ephemeral`, `sensitive` variable with no default through the write-only `password_wo` argument, so the value reaches neither state nor a plan file. Build context carries the same custody: three context-local ignore files keep the environment file, the `secrets/` directory, certificates, keys, credential JSON, virtual environments, dependency trees, caches and coverage out of every image layer, which `.gitignore` cannot do for an untracked file. The variable's own description is a custody control too: it names the environment variable and a gitignored variable file as the two supported channels and prohibits the command-line flag. `DL-369` carries that wording. The generated environment file is published with a link call that fails when the destination exists in any form, so a directory or symlink appearing at that path cannot absorb the file or be written through, and no check precedes the act. **Gaps**: no managed secret store, deployment still authenticates with a long-lived credential, and both container definitions still copy their whole context rather than an allow-list | `.gitignore`, `.env.example`, `SECURITY.md`, `.dockerignore`, `backend/.dockerignore`, `frontend/.dockerignore`, `infrastructure/docker/Dockerfile.backend`, `infrastructure/docker/Dockerfile.frontend`, `infrastructure/docker/docker-compose.yml`, `backend/app/core/config.py`, `.github/workflows/ci.yml`, `scripts/setup_dev_environment.sh`, `infrastructure/terraform/main.tf`, `infrastructure/terraform/variables.tf`, `infrastructure/terraform/.terraform.lock.hcl`, `backend/tests/security/test_config_guards.py` |
| **Prerequisite** | No dependency manifest, so the dependency surface had never been enumerated. CWE-1104. A06:2021 | `backend/requirements.txt` pins nineteen packages exactly, fourteen runtime and five for test and audit tooling. Two pins are load-bearing beyond version hygiene: `bcrypt==4.3.0` prevents a passlib capability probe that would break every password hash, and omitting a multipart parser keeps six advisories that cannot be patched on this runtime out of the closure | `backend/requirements.txt`, `.github/workflows/ci.yml` |

### 1.1 Final-acceptance findings

The acceptance gate that reviewed the thirteen rows above raised eleven further findings, three of
them major. They are identified `QA-01` through `QA-11`, the numbering the report supplied. None is
one of the twelve, so each carries its own row rather than being folded into a `SEC-NN` claim, and
the completeness check in section 3.1 covers them on the same terms. `DL-436` onward carry the
reasoning.

| Finding | Weakness and severity | Control that closes it | Files carrying the control |
| --- | --- | --- | --- |
| **QA-01** | Provider-to-model transform and scheduled updater could persist nothing. CWE-20, CWE-670. Major | The transform maps a provider record onto `ListingCreate`, the same writable-field allow-list the create route binds, so ingestion and the API validate through one contract and a provider key outside it is dropped rather than absorbed. The updater passes the zip codes the stored filters name, calls both synchronous helpers without `await`, matches a stored row on `zillow_url` — the only column carrying the provider's own reference — and stamps the two NOT NULL timestamps the server owns. One unusable record is skipped rather than costing the batch. **No column was added**, so the no-migration rule holds. The one-hour cadence and the `while True:` loop are unchanged | `backend/app/services/zillow_service.py`, `backend/app/tasks/listing_updater.py`, `backend/tests/security/test_zillow_ingestion.py` |
| **QA-02** | Unbounded outbound provider wait. CWE-1088, CWE-400. Major | Every provider call carries a bounded `(connect, read)` timeout, and an elapsed wait is caught in its own branch ahead of the general transport failure, so a stalled or never-answering upstream fails closed instead of holding the ingestion worker open | `backend/app/services/zillow_service.py`, `backend/tests/security/test_zillow_ingestion.py` |
| **QA-03** | Host-header URL reconstruction without validation, and a suppressed advisory accepted on a rationale that measurement contradicted. CWE-20, CWE-350. Major | `ALLOWED_HOSTS` is a required, validated allow-list of bare lowercase hosts: an empty list, the wildcard in any form, a subdomain pattern, and any entry carrying a scheme, userinfo, port, path, query or fragment all stop startup, so the comparison can never become a suffix test. The host middleware the pinned release already ships reads that list and is registered outside every other layer, with its redirect behaviour off, so an untrusted or malformed `Host` value is refused with 400 before routing reconstructs a URL from it. The published reachability of `PYSEC-2026-161` and `PYSEC-2026-248` is corrected in the same change: both now rest on an applied control rather than on a non-reliance claim. **Gap**: the comparison drops everything from the header's first colon, so an IPv6 literal cannot be expressed and is refused at startup; the fix release stays uninstallable until the runtime moves | `backend/app/core/config.py`, `backend/app/main.py`, `.env.example`, `infrastructure/docker/docker-compose.yml`, `SECURITY.md`, `backend/tests/security/test_host_validation.py` |
| **QA-04** | Published authentication mechanism names a credential endpoint that does not exist. CWE-1059. Minor | The schema document publishes the two channels the guard actually reads: a cookie scheme named for the session cookie and a bearer scheme, both optional so a cookie-only request still reaches the guard body. The OAuth2 password flow and its unreachable token URL are gone, and each guarded operation now declares both channels. Runtime token sourcing is unchanged, asserted across cookie-only, bearer-only, cookie-over-header, five unusable header spellings and no credential at all | `backend/app/core/security.py`, `backend/tests/security/test_openapi_contract.py` |
| **QA-05** | Enforced password policy undiscoverable from the published schema. CWE-1059. Minor | The password property carries the two bounds a schema keyword can express, a character minimum and a character ceiling at the byte number, plus one description naming the four character classes, the NUL refusal, the byte ceiling and the full special-character set. The byte-aware validator still decides, so nothing is weakened. The login model deliberately carries no bound, because one would answer 422 where every other credential refusal answers 401 | `backend/app/schema/user.py`, `backend/tests/security/test_openapi_contract.py` |
| **QA-06** | Frozen authentication response bodies published as empty schemas. CWE-1059. Minor | Each of the three routes publishes an object whose property and required sets are exactly the frozen key set, attached through the route's `responses` mapping rather than a `response_model`, so the body is documented without a filter being placed on a frozen contract. The published sets are asserted against the key sets the served responses carry | `backend/app/schema/user.py`, `backend/app/api/endpoints/auth.py`, `backend/tests/security/test_openapi_contract.py` |
| **QA-07** | Generated documentation pages fail basic accessibility checks. CWE-1059. Minor | Both pages are served from application-owned shells in place of the framework templates, on the same paths, with the same GET and HEAD verbs, the same schema exclusion and the same pinned bundle URLs. Each shell declares a document language, opens its body with an off-screen-until-focused skip link, and carries a banner, a navigation landmark naming the alternative page and the schema document, and a main landmark that takes focus so the link moves the keyboard caret rather than only the scroll position. Each also carries one level-one heading, which neither template emitted. What no template can reach is what each bundle renders at runtime, so each shell carries an attribute pass that runs after render and again on every re-render: it levels the one rank Swagger skips and the two ReDoc skips, gives every field an absent id and name, names each query-parameter field from the row describing it and each request-body editor, and marks every control-less `label` presentational. The pass adds attributes only where one is absent and replaces no markup. The callback path keeps its route and serves a static explanation, because the framework's script dereferenced a null opener on every direct visit. **Gap**: one browser autofill hint on the reference page counts `label` elements structurally and consults no ARIA, so it still reports thirteen; the accessibility tree ignores all thirteen | `backend/app/main.py`, `backend/tests/security/test_documentation_accessibility.py` |
| **QA-08** | The live database still grants `PUBLIC` the defaults the provisioning script revokes, so the application role can create temporary objects. CWE-250, CWE-269. Minor | The script's statements were already correct and reviewing them proved nothing: `init_database` stops at its `createdb` guard when the database exists, so both revokes and the read-back that follows them are skipped, and a database provisioned before they were written keeps the `CONNECT` and `TEMPORARY` a new database grants `PUBLIC`. A separate gate now carries only the statements that are safe to reissue — the two revokes against `PUBLIC`, the same two withdrawn from the application role directly, the four grants it does need and the two default-privilege statements — and closes with the same read-back block, byte for byte, that `init_database` uses. It runs standalone against an existing database and again as the closing privilege step of a full run, so the state is one command to correct rather than a procedure. A wrong answer raises inside the batch and the run ends non-zero; the gate never reports success on the strength of the statements it just sent. Measured on a live instance, `PUBLIC` lost both privileges, the application role kept `CONNECT` and lost `TEMPORARY`, `CREATE TEMP TABLE` moved from succeeding to `permission denied`, and permanent DDL stayed denied. **Gaps**: the gate has to be run — it corrects a server, not a deployment pipeline this repository does not own — and `PUBLIC` keeps schema `USAGE`, which the read-back admits deliberately because withdrawing it stops every role from resolving a table name | `scripts/setup_dev_environment.sh`, `SECURITY.md`, `backend/tests/security/test_config_guards.py` |
| **QA-09** | No security or cache-control headers on any response class, and a token-bearing answer that may be stored. CWE-693, CWE-1021, CWE-524, CWE-525. Minor | One layer registered outside every other adds the baseline set — `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy` and a content policy — to every response, so the host refusal, the preflight, the throttle refusal, the validation refusal, the framework 404 and the sanitized error each carry it rather than only the routes that reach a handler. Two of the headers are conditional rather than fixed. The content policy is closed for the API surface, which names no host and permits neither inline nor evaluated code, and names each CDN source for the two generated documentation pages, whose paths are read from the application's own doc URLs so a change to either cannot leave the policy behind. Two of those sources are reachable only from inside the bundles and so were found by a browser rather than by reading markup, and `connect-src` names every origin `script-src` already trusts to execute, which is an invariant the suite asserts rather than a string it transcribes. `Strict-Transport-Security` is sent only when the request arrived over TLS, so the header is never a claim the connection cannot support. A header the response already carries is left alone, so a route may narrow its own policy further. The three token-bearing routes answer `Cache-Control: no-store` with `Pragma: no-cache` on the same response that sets or clears the session cookie, while the public read path stays cacheable. **Gaps**: the transport claim still depends on the TLS edge terminating HTTPS, and `Cross-Origin-Resource-Policy` is deliberately absent because the client reads this API in cors mode, which SEC-03 already bounds by origin | `backend/app/main.py`, `backend/app/api/endpoints/auth.py`, `backend/tests/security/test_response_headers.py` |
| **QA-10** | Two operator documents publish credential-scan metrics that the tree outgrew. CWE-1059. Minor | Both documents stated twenty-one matched lines and four marked ones against a tree carrying more of each, which is the failure mode a published metric has: it is read instead of run, and it goes stale silently as the tree grows. Both now state the same four numbers — lines matched, lines the allow-list leaves, matched lines carrying the reviewed-line marker, and marker occurrences in tracked content — and a case regenerates all four from the tracked tree using the workflow's own pattern and allow-list, then compares them against each document with its whitespace collapsed, so rewrapping a paragraph cannot break the comparison and a stale number cannot survive a test run. The counts are no longer dated, because a generated number needs no date. Measured: twenty-four matched, zero left by the allow-list, eight marked, ten marker occurrences of which two are the workflow's own declarations. **Gap**: the case pins the numbers, not the surrounding prose, so a classification sentence beside them can still drift | `SECURITY.md`, `backend/tests/security/test_config_guards.py` |
| **QA-11** | Repository and specification documents publish addresses that do not resolve. CWE-1059. Minor | Six references failed: two placeholder repository URLs answered 404, three `api.zillow.com` addresses did not resolve at all, and the retired provider documentation page answered 403. The two repository URLs become bracketed templates in the form `.env.example` already uses, so nothing reads as a resolvable address. The three provider endpoints inside the specification snippets become the `ZILLOW_API_URL` setting the shipped client actually reads, which removes the dead host and makes the specification agree with the implementation; each snippet now imports the settings object it references. The reference-list entry points at the provider's own developer entry point, verified to answer 200, and states plainly that the public API this specification was drafted against has been retired. The broken licence-file link is withdrawn and the fabricated maintainer identity replaced with the channels this repository actually has. Every external address remaining in the three documents answers 200, and no tracked relative link is broken. **Gaps**: the licence statement still names a licence the repository tracks no file for, and no maintainer contact is published, because neither can be supplied without inventing it | `README.md`, `documentation/Software Requirements Specifications (SRS).md`, `documentation/Technical Specifications.md` |

---

## 2. Direction B — file to control to finding

One row per delivered path, fifty-eight in all, grouped by directory: the thirty-nine of the planned
change set plus the nineteen delivered outside it, which section 3.4 names with their departure
recorded. **Mode** is `CREATE`, `UPDATE`
or `REFERENCE`, where a reference file is read as an authority and deliberately left unchanged, and a
mode reading *delivered* differs from the plan. Controls are named, not re-explained; section 1 holds
the mechanism.

### 2.1 Repository root

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `.gitignore` | CREATE | Excludes the environment file, the secrets directory, certificates, keys and credential JSON, plus Terraform state and variable files. `password_wo` from an `ephemeral` variable keeps the database password out of both state and plan, so these two exclusions stand on the variable file being the conventional home for an operator-supplied value and on state recording other resource attributes | SEC-01, SEC-11, SEC-12 |
| `.env.example` | CREATE | Documents every required variable by name, shape and purpose, including the JSON-array form the origin list expects. Secrets and deployment-specific identifiers appear as angle-bracket placeholders; the rest are documented non-secret defaults and required choices, so no line carries a real credential. Carries both contracts: the backend settings, and a final section naming the two frontend build variables the client bundle embeds | SEC-01, SEC-03, SEC-10, SEC-12, QA-03 |
| `.dockerignore` | CREATE | The root build context, and the widest of the three ignore files: it also excludes both sub-context caches, virtual environments, dependency trees and the frontend build and coverage output. Excludes the environment file and its temporary form, the `secrets/` directory, certificates, keys and credential JSON, so a broad `COPY . .` cannot carry an untracked secret into an image layer | SEC-12 |
| `backend/.dockerignore` | CREATE | The context `Dockerfile.backend` builds from, whose `COPY . .` would otherwise carry the whole backend tree. Excludes the same secret-bearing paths, plus the Python caches, egg metadata, virtual environments and coverage output | SEC-12 |
| `frontend/.dockerignore` | CREATE | The context `Dockerfile.frontend` builds from, whose `COPY . .` would otherwise carry the whole frontend tree. Excludes the same secret-bearing paths, plus `node_modules/`, `build/` and `coverage/` | SEC-12 |
| `SECURITY.md` | CREATE | Operator-facing custody procedure, verification commands, residual-risk register and the deferred follow-ons. Section 3.2 also carries the out-of-band `REVOKE` and `GRANT` statements that reduce the Cloud application account, which no provider resource can express | SEC-11, SEC-12, QA-03, QA-08, QA-10 |
| `README.md` | **UPDATE, delivered** | Publishes no address that fails to resolve: the clone URL is a bracketed template, the broken licence-file link is withdrawn with the gap stated, and the fabricated maintainer identity is replaced by the issue tracker in template form and a pointer to the security procedure | QA-11 |

### 2.2 Backend application

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `backend/requirements.txt` | CREATE | Nineteen exact pins, including the availability-critical `bcrypt==4.3.0`; unblocks `Dockerfile.backend` and the pipeline install step, both of which already referenced this file | Prerequisite (CWE-1104) |
| `backend/app/core/config.py` | UPDATE | Validated security settings: the required origin allow-list, the payment-mode domain, the transport mode, the cookie flag, the limiter thresholds, the signing-key floor and the three settings that previously raised `AttributeError` | SEC-03, SEC-06, SEC-07, SEC-09, SEC-10, SEC-12, QA-03 |
| `backend/app/main.py` | UPDATE | Explicit method and header lists on the cross-origin middleware, the limiter registration and its exceeded handler, the four global exception handlers, and the record factory that folds every application record to one line before propagation. Carries the outermost response-header layer, the two content policies it chooses between and the conditional transport claim, and the three documentation shells that replace the framework templates on their own paths. Also corrects the import source for `Base`, which is boot-blocker layer four | SEC-03, SEC-07, SEC-08, QA-03, QA-07, QA-09 |
| `backend/app/core/security.py` | UPDATE | Integer coercion of the subject inside a 401 guard, the uniform 401 with `WWW-Authenticate: Bearer`, the `iat` claim, and the cookie-before-header read | SEC-02, SEC-06, SEC-08, QA-04 |
| `backend/app/api/endpoints/auth.py` | UPDATE | Mints the subject as the user identifier, binds `UserCreate` and `UserLogin` so the password reaches a validating allow-list before hashing, sets and clears the session cookie, adds `POST /auth/logout`, and applies the login limit keyed on the exact stored identity. Both credential branches perform one fixed-cost verification, against a per-process random stand-in hash when no row matches. Marks each answer that mints or revokes a session uncacheable, on the same response that carries the cookie. Also supplies the non-null `created_at` without which registration always failed | SEC-02, SEC-04, SEC-05, SEC-06, SEC-07, QA-06, QA-09 |
| `backend/app/api/endpoints/listings.py` | UPDATE | The model import at `:7` extends to include `User`, resolving the annotation at `:18` and clearing boot-blocker layer two. The same signature binds `ListingCreate`, so the allow-list reaches the expansion at `:21`; see the SEC-05 row in section 1. The route answers a sanitized 500 and persists nothing, for the schema reasons section 3.4 records | Enabling repair, SEC-05 |
| `backend/app/schema/user.py` | UPDATE | Strict create and login models, the password policy with its byte ceiling, the integer identifier, and removal of the password-hash field from the outbound model | SEC-02, SEC-04, SEC-05, QA-05, QA-06 |
| `backend/app/schema/filter.py` | UPDATE | Strict allow-list of writable filter fields, applied to the nested criteria as well | SEC-05 |
| `backend/app/schema/listing.py` | UPDATE | Strict allow-list of writable listing fields, the control for the mass-assignment site, with a finiteness check on each declared float so a non-finite literal is refused at the boundary rather than stored | SEC-05 |
| `backend/app/schema/subscription.py` | CREATE | Supplies the create and response models the subscription endpoint already imported from a module that did not exist. Boot-blocker layer one | SEC-05 |
| `backend/app/db/database.py` | UPDATE | Passes the transport mode through `connect_args`, conditionally and only for PostgreSQL URLs | SEC-10 |
| `backend/app/services/paypal_service.py` | UPDATE | Reads the payment environment from the validated setting, and carries the charge verifier: a reference is claimed in a local ledger, resolved through the provider under a bounded transport, bound to state, amount, currency, payer and plan, then recorded in a bounded worker-local ledger. A replay is refused while the digest is retained, and not after eviction or a restart. Also adds the missing typing import for both annotation sites and the async wrapper the subscription endpoint calls, clearing boot-blocker layers two and three | SEC-09 |
| `backend/app/services/zillow_service.py` | **UPDATE, delivered** | Bounds the outbound provider wait with a `(connect, read)` pair and catches an elapsed wait in its own branch. Carries the one authoritative provider-to-model mapping: the provider key spellings each writable column is read from, the readers that turn a quoted, formatted feed value into a JSON number or a non-empty string, and construction through `ListingCreate`, so the allow-list decides what reaches a column. Refuses a record supplying no value for the one NOT NULL writable column. Planned outside the map; see section 3.4 | QA-01, QA-02 |
| `backend/app/tasks/listing_updater.py` | **UPDATE, delivered** | Passes the zip codes the stored filters name, calls both synchronous helpers without `await`, drops the coroutine decorator removed from the language, matches a stored row on the provider reference the model actually declares, writes only the columns the provider supplied, and stamps both server-owned timestamps. Skips one unusable record rather than rolling back the batch. Reads the stored filters and writes nothing back to them. Planned outside the map; see section 3.4 | QA-01 |
| `backend/app/db/models.py` | REFERENCE | The authority for column types and nullability, and the reason no schema change is proposed: with no migration tooling, a new column or default never reaches an existing table. Verified byte-identical | Authority for SEC-02, SEC-05 |
| `backend/app/api/endpoints/filters.py` | UPDATE | Copies the validated allow-list onto mapped `Criteria` children and supplies the server-owned `created_at`, so a request cannot set either through the relationship. Also the reference pattern for a declared `response_model`, the one write endpoint that already had one. Delivered beyond the planned mode, see section 3.4 | SEC-05 |
| `backend/app/api/endpoints/subscriptions.py` | **UPDATE, delivered** | Binds the requested plan on the charge call at `:24`, which is what gives the verifier's plan check a value to compare; a reusable agreement for another plan is otherwise indistinguishable from one for this plan. Also the authority whose import at `:7` and its call site dictated the wrapper signature added to the payment service, and whose import at `:4` names the models the created `schema/subscription.py` had to export. Planned REFERENCE; see section 3.4 | SEC-09, authority for SEC-05 |

### 2.3 Backend tests

Every file here is a vulnerability regression test: each asserts that one specific weakness is no
longer exploitable.

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `backend/tests/conftest.py` | CREATE | The harness the other eight depend on: dual import paths, environment injection before the application is imported, a real SQLite session override, and an HTTPS base URL so a `Secure` cookie persists under test | Verification for SEC-02 to SEC-12 |
| `backend/tests/security/test_auth_identity.py` | CREATE | Asserts the subject round-trip, that an email subject is refused with 401 rather than 500, that an unresolvable subject answers 401 rather than 404, and that `iat` is present. Its authenticated-route case runs against `POST /filters/`, which persists, so the case asserts a stored row rather than a tolerated failure | SEC-02 |
| `backend/tests/security/test_cors_policy.py` | CREATE | Asserts an allow-listed origin is echoed with credentials, a foreign origin receives no allow-origin header, and an unsafe configuration prevents startup | SEC-03 |
| `backend/tests/security/test_password_policy.py` | CREATE | Asserts rejection below twelve characters, for each missing character class, and above the byte ceiling, plus acceptance of a compliant password | SEC-04 |
| `backend/tests/security/test_input_validation.py` | CREATE | Asserts an unknown field is rejected with 422, which is the mass-assignment assertion, that malformed, missing and wrongly typed fields never produce a 500, and that a non-finite number is refused for every declared float. Also executes the shipped frontend client against a recording transport, driving it with the form component's own value, so the mapping asserted is the one that ships | SEC-05, SEC-06 |
| `backend/tests/security/test_token_storage.py` | CREATE | Asserts the three cookie attributes, that the JSON body keeps its exact key set, that a cookie-only request authenticates, that the bearer fallback still works, and that logout clears the session cookie so a later cookie-only request is rejected | SEC-06 |
| `backend/tests/security/test_login_throttle.py` | CREATE | Asserts that the sixth consecutive failed login returns 429, that the throttled body uses the uniform envelope, and that throttled attempts are logged. Two stored accounts differing only in local-part case hold separate counters, and a success on one neither clears nor exhausts the other. An unknown address and a wrong password are asserted to do equal work at the hasher, by invocation count rather than by wall clock | SEC-07 |
| `backend/tests/security/test_error_handling.py` | CREATE | Asserts a sanitized 500 carrying no traceback or internal detail, a 422 carrying field names only, envelope uniformity across handlers, and a correlation identifier in both response and log. A root handler with a stock formatter is attached and asserted to receive exactly one line, which is the assertion a formatter on the owned handler alone cannot satisfy | SEC-08 |
| `backend/tests/security/test_config_guards.py` | CREATE | Asserts the payment-mode domain, the signing-key length floor, and that the transport argument is applied for PostgreSQL and withheld for SQLite. It drives the charge seam and the subscription route through their production paths, in both the authorizing and the refusing direction. It asserts that a reference retained in the ledger authorizes no second charge, which is the bound that ledger's 4,096-digest capacity and per-worker lifetime allow. It holds the privilege split by reading the shipped statements: the granted set compared whole, both `PUBLIC` revokes present, no broad privilege conferred, and no role password in a process argument list. It also asserts the batch's own effective-access verification is present, which `DL-355` returns to the suite separately. It executes the provisioning publish against a destination planted after the source exists, in three forms. It reads the pipeline's own expressions and executes both gates against planted controls. And it asserts the build definitions are consumable: each named image definition exists, no declared value interpolates to empty, the backend receives every required setting, and the exposed, published and probed ports agree. It reads the throttle's key source out of the served command too, so the flag that keeps the limiter keyed on the connection cannot be dropped without a failing case, and it holds the operational document to recording that posture | SEC-01, SEC-07, SEC-09, SEC-10, SEC-11, SEC-12, QA-08, QA-10 |
| `backend/tests/security/test_zillow_ingestion.py` | **CREATE, delivered** | Drives a mocked provider through fetch, transform, database write and read back, in both the insert and the update direction, and asserts that an omitted column keeps its stored value and that an unusable record costs only itself. Pins the bounded outbound wait against a real server that answers late and a real server that never answers, and asserts the frozen one-hour cadence. Planned outside the map; see section 3.4 | QA-01, QA-02 |
| `backend/tests/security/test_host_validation.py` | **CREATE, delivered** | Drives the two hostile `Host` values the acceptance gate used against all three slash-redirecting routes and asserts a 400 with no `Location`, drives three lookalike hosts to assert the match is equality rather than a suffix test, asserts an absent header is refused, asserts the trusted host keeps both its redirect and the public read path, asserts nineteen unsafe allow-list values stop startup and four safe ones construct, and asserts the registered middleware carries the configured list with its redirect behaviour off. Planned outside the map; see section 3.4 | QA-03 |
| `backend/tests/security/test_openapi_contract.py` | **CREATE, delivered** | Asserts the document against the running application rather than against a transcription: no scheme names a token URL and the previously advertised path is still absent, the two published schemes are the two the guard reads and a guarded operation declares both, token sourcing is unchanged across every header and cookie permutation, the password property carries both bounds and a description naming every rule a keyword cannot express while the login property carries neither, eight non-compliant passwords are still refused with no echo, and each published response key set equals the key set the served response carries while all three routes still declare no response model. Planned outside the map; see section 3.4 | QA-04, QA-05, QA-06 |
| `backend/tests/security/test_response_headers.py` | **CREATE, delivered** | Drives every response class the acceptance gate inspected — the four framework paths, the public read, all three authentication answers, a protected 200 and 401, a preflight, a validation refusal, a framework 404, a throttle refusal, a sanitized 500 and a host refusal — and asserts the baseline set is present and exact on each. Asserts the layer is the outermost registered one, that the documentation path set is the application's own, that each origin the two generated pages actually load is named by the policy they are served under, that the closed policy names no host and permits no inline or evaluated code, that the transport claim is present over TLS and absent over plain HTTP, that only the token-bearing answers forbid storage while the public read stays cacheable, that a header the response already carries is preserved, and that no response repeats a header. Planned outside the map; see section 3.4 | QA-09 |
| `backend/tests/security/test_documentation_accessibility.py` | **CREATE, delivered** | Asserts the markup all three shells emit — the document language, the banner, navigation and main landmarks, the skip link opening the body, the focusable skip target, the off-screen-until-focused rule and the one level-one heading — and that the shells load the same asset URLs the framework named, so owning the markup cannot silently move a bundle version. Asserts each half of the runtime attribute pass, that it observes its mount point so a re-render is covered, and that it replaces no markup and removes no attribute. Asserts the three paths and their GET and HEAD verbs did not move, that none enters the schema, that the framework can serve no template of its own on them, that each navigation names the alternative page and the schema, that the reference shell keeps a scriptless fallback, that the callback page carries no script at all and its headings need no correction, and that no shell emits an inline event handler. Planned outside the map; see section 3.4 | QA-07 |


| `backend/tests/test_api.py` | REFERENCE | The authority for existing harness conventions. Verified byte-identical, and it still fails collection with the same import error as before, so the new harness did not change its outcome | Authority for the harness |

### 2.4 Frontend

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `frontend/src/services/auth.ts` | UPDATE | Removes all browser token storage, corrects the request path to `/auth/login`, and delegates logout to the server route that can clear an `HttpOnly` cookie. Declares the authentication response contract the frozen login body actually carries, as the exported `AuthSession` type, in place of a user object the body has never held | SEC-06 |
| `frontend/src/services/api.ts` | UPDATE | Exports the base URL that the auth module already imported, and sends credentials so the browser transmits the session cookie; the cross-site-token option is deliberately left unset. Declares the wire type of each response instead of casting to one, maps the filter form's own value onto the writable-field allow-list before sending it, and declares no path the application does not serve — the call to an unmounted profile route is gone | SEC-06, SEC-05 |
| `frontend/src/schema/listing.ts` | **UPDATE, delivered** | Exported declaration of the body the read path actually carries: an integer key, snake_case names, ISO-8601 date-time strings and null for every nullable column. Also declares `ListingQuery`, the two pagination bounds that path reads, so no other query parameter is assumed | SEC-05 |
| `frontend/src/schema/filter.ts` | **UPDATE, delivered** | Exported declaration of the filter body, with a separate `FilterCreate` naming the writable fields the create path accepts. Also declares the form's own value shape, so the mapper's input is a contract rather than an assumption | SEC-05 |
| `frontend/package.json` | UPDATE | One line: the axios caret range becomes an exact pin, removing a declared floor that sat inside the CVE-2023-45857 range now that credentialed mode is enabled | SEC-06 prerequisite |
| `frontend/src/components/ListingCard.tsx` | **UPDATE, delivered** | Binds the field names the read path publishes, so no value reaches the document as the literal `undefined`, and gates the outbound link on an `http` or `https` scheme, so a stored `javascript:` value renders as inert text with no `href` rather than executing in the document. The image element is removed because no image column exists to source it. Delivered outside the planned map; section 3.4 records it | SEC-05 |
| `frontend/src/utils/validators.ts` | REFERENCE | The authority for the password character set at `:18-32`, mirrored by the server validator so the two cannot drift. Verified byte-identical | Authority for SEC-04 |

### 2.5 Infrastructure and provisioning

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `infrastructure/docker/Dockerfile.frontend` | UPDATE | Declares a build argument for each frontend build variable ahead of `npm run build`, so both reach the bundle from the build environment and neither is a literal in the image definition. Resolves the install from the tracked manifest alone, since no lock file is tracked and an install demanding one cannot run from a clean checkout | SEC-12 |
| `infrastructure/docker/Dockerfile.backend` | **UPDATE, delivered** | Places the build context where the application's own package path resolves and starts the process above it, so the image runs the module the application declares rather than one that does not exist, and exposes the port the definition publishes. The served command also carries the throttle's key source: `--no-proxy-headers` keeps the login limiter keyed on the connection rather than on a header a caller can write, which is section 1's SEC-07 row seen from the deployment side. Planned outside the map; see section 3.4 | SEC-07, SEC-12 |
| `infrastructure/docker/docker-compose.yml` | UPDATE | Environment indirection in the fail-closed `${VAR:?message}` form for every build argument and every no-default setting, the corrected secret variable name, the complete backend settings contract, and the documented local transport exception for the Auth Proxy topology. Each service names the image definition that exists relative to its context, and each healthcheck names a program its own base image carries | SEC-01, SEC-10, SEC-12, QA-03 |
| `infrastructure/terraform/main.tf` | UPDATE | The encryption-only IP configuration on the Cloud SQL instance, a separate application database account whose password reaches neither state nor a plan file, and the bounded provider and command-line ranges that pair with the tracked lock. It carries no privilege restriction, which is a provider limit rather than an omission; `DL-350` and `DL-368` carry both | SEC-10, SEC-11, SEC-12 |
| `infrastructure/terraform/.terraform.lock.hcl` | **CREATE, delivered** | The provider selection itself: one directory hash for each of the four platforms an operator or the pipeline installs from, the registry checksum set, and the constraint the configuration declared when it was generated. A range admits many builds; this file chooses one. Planned outside the map; see section 3.4 | SEC-10, SEC-11, SEC-12 |
| `infrastructure/terraform/variables.tf` | UPDATE | The application account's name, its write-only password and the counter that reapplies a rotation. Each one is read by `main.tf`; the configuration declares no variable it never reads. The password variable's description names the two supported input channels and prohibits the command-line flag that would expose the value in the process arguments and in shell history | SEC-11, SEC-12 |
| `scripts/setup_dev_environment.sh` | UPDATE | Generated rather than literal credentials, published with a link that fails when anything already stands at the destination, and the owner plus application role split that replaces the unrestricted grant. Both default `PUBLIC` privilege sets are revoked, and the batch closes by reading the effective access lists and raising if they disagree. Three of the four original credential-scan hits were in this file | SEC-01, SEC-11, SEC-12, QA-08 |

### 2.6 Pipeline

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `.github/workflows/ci.yml` | UPDATE | The four enforcement gates, and the authoritative definition of each scan pattern. The dependency audit carries its justified suppressions and a staleness check that reads both identifiers and aliases from the audit's own report. The credential scan runs in two stages: a pattern matching an assignment with or without spaces and quotes, then a reviewed allow-list. The other two are the frontend client-secret guard and the browser-storage guard. Its frontend install resolves from the manifest exactly as the image does. `DL-345`, `DL-207`, `DL-208`, `DL-209` and `DL-210` carry the five | SEC-01, SEC-06, SEC-09, SEC-12, Prerequisite |

### 2.7 Security documentation

Both files here trace to **Rule 1 (Explainability)** rather than to a finding. Neither appears in any
of the twelve, and their presence is a rule obligation rather than a coverage gap.

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `documentation/security/decision-log.md` | CREATE | The four-column decision table: what was decided, what alternatives existed, why the choice won, and what risk it leaves. The single source of truth for rationale. Section 40.8 carries the Rule 2 prose scorecard for the file, with its verdict and the measurements behind it | Rule 1 and Rule 2, not a finding |
| `documentation/security/traceability-matrix.md` | CREATE | This file. The bidirectional finding-to-file map that makes the coverage claim checkable | Rule 1, not a finding |

### 2.8 Project specifications

These two trace to **QA-11**. Neither appears in any of the twelve, and neither was planned: an acceptance gate probed every address they publish and found the provider host gone.

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `documentation/Software Requirements Specifications (SRS).md` | **UPDATE, delivered** | Two provider snippets read the endpoint and the key from configuration rather than from a host that no longer resolves, each importing the settings object it references, and the reference-list entry points at an address that answers | QA-11 |
| `documentation/Technical Specifications.md` | **UPDATE, delivered** | The provider snippet reads the endpoint and the key from configuration rather than from a host that no longer resolves, and imports the settings object it references | QA-11 |

---

## 3. Coverage reconciliation

### 3.1 The arithmetic

The table below is the **planned** map, which was written before the acceptance gate raised the
eleven findings in section 1.1. Delivery departs from it on two paths and adds fourteen; section
3.4 carries every departure, and `DL-391` carries the decision behind the delivered arithmetic.

| Mode | Count | Where they sit |
| --- | --- | --- |
| CREATE | 16 | 3 at the repository root, 11 under `backend/`, 2 under `documentation/security/` |
| UPDATE | 18 | 10 under `backend/`, 3 under `frontend/`, 3 under `infrastructure/`, 1 under `scripts/`, 1 under `.github/` |
| REFERENCE | 5 | 4 under `backend/`, 1 under `frontend/` |
| DELETE | 0 | See section 3.2 |
| **Total** | **39** | Each has its own row in section 2, which carries 58 |

**Coverage is stated as measured, not asserted.** An edge-set comparison extracted from the two
sections reports **116 edges in Direction A and 116 non-exempt edges in Direction B, with an empty
difference in both directions**. It also reports **5 exempt edges across the 6 declared-asymmetric
rows** below, and **58 unique paths in 58 rows, at 25 CREATE, 30 UPDATE and 3 REFERENCE**. `DL-395`
carries the decision to state the claim this way, and `DL-403` the row split that made those two
counts equal.

What that measurement covers: every one of `SEC-01` through `SEC-12`, and every one of `QA-01`
through `QA-11`, has at least one file in section 1, and every file in section 2 traces to a finding,
to the dependency prerequisite, to an enabling repair, or to Rule 1. No section-1 claimant is missing
the finding from its section-2 row, and no section-2 row carries a finding its section-1 claimant
list omits.

Six rows are deliberately asymmetric, and a cross-check has to allow for them. Three REFERENCE rows
read `Authority for` and the harness row reads `Verification for`; those four files supply an authority
or the scaffolding the assertions run on, and none carries a control. The two security documents carry
a Rule 1 obligation rather than a finding, as section 2.7 states. All six appear in section 2 against
findings whose section-1 claimant lists do not name them. Every other row is symmetric, the thirteen
regression-test files, `filters.py` and `subscriptions.py` included; `DL-390` carries the reconciliation
that made the last three of them so.

Version control settles the delivered mode of every row. Measured against the last pre-work commit,
each CREATE is absent there, each UPDATE differs from it, and three of the five paths planned as
REFERENCE are byte-identical to it. Two carry controls instead: `backend/app/api/endpoints/filters.py`
carries a SEC-05 control and `backend/app/api/endpoints/subscriptions.py` binds the requested plan on
the charge call, so section 2 records both as delivered updates. Sixteen further paths the map never
listed are delivered: the three build-context ignore files, both image definitions, the provider
lock, both frontend schema declarations, the listing card, the provider client, the scheduled updater,
and the five regression suites the acceptance findings required. Section 3.4 states every departure
and records what else the branch touches.

### 3.2 Zero deletions, stated deliberately

No file was deleted, and the zero is a finding rather than an empty cell. No file in this repository
introduces a weakness that removal would fix: every one of the twelve is closed by correcting, adding
or configuring. A reviewer checking completeness should be able to see that the absence of a deletion
was decided rather than overlooked.

One removal did happen, one level down. A multipart parser was left out of the new manifest rather
than pinned, which closed six advisories that no version available on this runtime could close. That
is a dependency decision, not a file deletion.

### 3.3 Files whose absence is the point

Three of the five paths planned as references are read as authorities and deliberately left unchanged:
`backend/app/db/models.py`, `frontend/src/utils/validators.ts` and `backend/tests/test_api.py`. All
three are byte-identical to the last pre-work commit, so each was consulted and then left alone rather
than missed.

No column and no default was added to the model file, and the filter repair in section 3.4 adds none
either. `DL-247` carries that decision and the three capabilities it defers.

### 3.4 Plan versus delivery

**Delivery departs from the planned classification on seventeen paths, and the table below carries
every one.** Across the 39 planned paths: 16 created, **20 updated, 3 references left
byte-identical**, no deletions — the two differences being
`backend/app/api/endpoints/filters.py` and `backend/app/api/endpoints/subscriptions.py`, both planned
REFERENCE and both delivered UPDATE.

**Sixteen further paths are delivered outside the map**: the three build-context ignore files, the
Terraform provider lock, both image definitions, both frontend schema declarations, the listing
card, and the seven paths the acceptance findings in section 1.1 reach — the Zillow provider client,
the scheduled updater, their regression suite, the host-validation suite, the API-contract suite,
the response-header suite and the documentation-accessibility suite.
Nine of the sixteen are new files and seven are modifications, measured against the last pre-work commit. Delivered totals
are therefore **25 created, 27 updated, 3 byte-identical references, 55 paths**, which is what the edge-set comparison
in section 3.1 recomputes from this file. `DL-391` carries the decision, and `DL-436` onward the
acceptance-finding paths.

Three of those departures were withdrawn by an earlier pass and all three are restored here. A
withdrawal and a restoration are each a decision in their own right rather than a quiet tidy-up.

| Path | Planned | Delivered | What changed, and where the reasoning sits |
| --- | --- | --- | --- |
| `backend/app/api/endpoints/filters.py` | REFERENCE | **UPDATE, delivered** | The endpoint carries a SEC-05 control the planned mode did not anticipate: the validated allow-list is copied onto mapped `Criteria` children and `created_at` stays server-owned. An earlier pass withdrew this to keep the mode column exact and lost the only write path that persists, so the repair is back and the mode column is corrected instead. No column was added or retyped. Log section 40, `DL-296` and `DL-297`, which supersede `DL-286` |
| `backend/app/api/endpoints/subscriptions.py` | REFERENCE | **UPDATE, delivered** | The caller binds the requested plan on the charge call again. It was withdrawn with the verifier it depended on, and the verifier is back: without the binding, a reusable agreement for any plan authorizes a charge for any other, so the caller edit is part of the control rather than a convenience. Log section 41, `DL-332`, which supersedes `DL-288` for this path |
| `infrastructure/docker/Dockerfile.backend` | not planned | **UPDATE, delivered** | The definition started a module that does not exist and exposed a port the Compose file did not publish, so a container built from it either failed to start or was probed on the wrong port. Both are corrected, with the context placed where the application's own package path resolves. Log section 41, `DL-347` |
| `infrastructure/terraform/.terraform.lock.hcl` | not planned | **CREATE, delivered** | The encryption argument and the write-only password pair are provider features, and an untracked lock left the selection of that provider to whatever a clean checkout happened to resolve. The lock is generated for four platforms and tracked. Log section 41, `DL-349` and `DL-350` |
| `infrastructure/docker/Dockerfile.frontend` | not planned | **UPDATE, delivered** | The client bundle embeds `REACT_APP_API_BASE_URL` and `REACT_APP_PAYPAL_CLIENT_ID` at compile time, so the only place they can be supplied is this file's build stage. The template calls itself authoritative for every variable, which it could not be while these two had nowhere to arrive. The same file also carries the pinned Node line, raised for a platform runtime floor. Log section 40, `DL-309` and `DL-310` |
| `.dockerignore`, `backend/.dockerignore`, `frontend/.dockerignore` | not planned | **CREATE, delivered** | Three paths outside the planned map carry a SEC-12 control the map did not anticipate. `Dockerfile.backend:14` and `Dockerfile.frontend:14` both run `COPY . .`, so without them every path in a build context enters the image, an untracked `.env` included — the one secret `.gitignore` cannot reach. An earlier pass removed them to keep the path count exact and reopened that route. Log section 40, `DL-300` and `DL-301`, which supersede `DL-287` and reinstate `DL-127` through `DL-129` |
| `frontend/src/schema/listing.ts`, `frontend/src/schema/filter.ts` | not planned | **UPDATE, delivered** | Two paths outside the planned map carry a SEC-05 control. Each declares the body its read or write path actually carries — integer identifiers, snake_case names, ISO-8601 date-time strings — and `filter.ts` adds a `FilterCreate` naming the writable fields plus the form's own value type. The client sends that allow-list rather than a cast object. Log section 40.3, `DL-306` and `DL-308`; the section scope line there names both files literally |
| `backend/app/services/zillow_service.py`, `backend/app/tasks/listing_updater.py`, `backend/tests/security/test_zillow_ingestion.py` | not planned | **UPDATE, UPDATE, CREATE, delivered** | The acceptance gate found the ingestion path unable to persist anything and its outbound call unbounded, and put both in scope as major findings. The plan named neither file, because the twelve findings did not reach them: `SEC-08` records the stdout print in the provider client as noted rather than fixed, and nothing in the twelve touches the updater. The frozen ingestion contract is what the plan protects, and it survives — the one-hour cadence, the loop, the two public function names and the fetch signature are unchanged, and no column was added. Log section 48, `DL-436` to `DL-438` |
| `backend/tests/security/test_host_validation.py` | not planned | **CREATE, delivered** | The acceptance gate demonstrated that a suppressed advisory the plan had recorded as relying on nothing was in fact reachable through the framework's own trailing-slash redirect. The plan named a host allow-list as an available compensating control and expressly did not mandate it; the measurement is what changed that answer, so the control is applied and this suite is what keeps it applied. Log section 48, `DL-439` and `DL-440` |
| `backend/tests/security/test_openapi_contract.py` | not planned | **CREATE, delivered** | Three acceptance findings concern the published contract rather than behaviour, and prose cannot hold a contract to a running application. Every assertion in this module reads the served document and compares it against the served responses, which is what makes the three closures re-derivable rather than transcribed. Log section 48, `DL-441` to `DL-443` |
| `backend/tests/security/test_documentation_accessibility.py` | not planned | **CREATE, delivered** | The plan named no documentation markup, because the framework generated it and the twelve findings did not reach accessibility at all. The acceptance gate loaded both pages at four widths and found a missing document language, absent landmarks, no skip link, a skipped heading rank and unnamed controls. Owning the markup is the only way to reach any of those, and owning it is also what makes a regression possible, which is what this suite exists to prevent: it pins the paths, the verbs, the schema exclusion, the asset URLs and every half of the runtime pass. Log section 48, `DL-446` and `DL-447` |
| `backend/tests/security/test_response_headers.py` | not planned | **CREATE, delivered** | The plan named no response-header policy, and the twelve findings did not reach one: SEC-03 bounds who may read a response and SEC-08 bounds what a response says, but neither instructs the browser about sniffing, framing, referrers or storage. The acceptance gate measured every checked header absent from every response class, which is what put the layer in scope. A header set is only worth what it is measured on, so this suite drives each of those classes rather than one representative route, and pins the two conditional headers in both directions. Log section 48, `DL-444` and `DL-445` |
| `README.md`, `documentation/Software Requirements Specifications (SRS).md`, `documentation/Technical Specifications.md` | not planned | **UPDATE, UPDATE, UPDATE, delivered** | The plan named no repository or specification prose, because the twelve findings concerned code, configuration and infrastructure. The acceptance gate probed every address these three publish and found six that fail: two placeholder repository URLs answering 404, three provider endpoints whose host does not resolve, and a retired documentation page answering 403. A specification that instructs a reader to call a host that no longer exists is a defect in the specification, and the correction points the snippets at the setting the shipped client already reads, so the two agree. Log section 48, `DL-451` |

Sections 2 and 3.1 state the planned scope. Where delivery exceeds it, the excess is a control this
table names rather than a difference a reader has to find in a diff, and section 2 carries a row for
every delivered path.

Four further withdrawals in an earlier log section changed content without changing any
classification, so they carry no row above. The provider logger stayed capped while the transport
replacement beside it went. The pagination bounds and the listing-side value ranges went while the
wire-type guards stayed. The advisory register settled at fifteen entries, and the login throttle was
recorded as it ships. Log section 38 carries all seven of that pass's withdrawals, `DL-286` through
`DL-292`.

Two of them were reversed by the security assessment that followed, and both reversals are rows
above. The payment service's charge verifier is back. The listing-side finiteness check is back as a
type-domain check that keeps a non-finite literal out of a float column, not as the value range, which
stays withdrawn. Log section 41, `DL-332` and `DL-335`.

### 3.5 What this matrix deliberately omits

Weaknesses found during the work but not fixed carry no file, so they have no row here. They are
recorded instead in [`decision-log.md`](decision-log.md) section 34, with the operator-facing view in
[`SECURITY.md`](../../SECURITY.md) section 3.4. Their absence from this matrix is deliberate and is
not a coverage gap.

The three documents also give three different counts for that list, and the reason is worth one
sentence. One observation on the original list was closed rather than deferred. The outbound user
model no longer declares a password-hash field, removed alongside the SEC-02 identity correction
because the same model was already being edited. It therefore appears in this matrix, under
`backend/app/schema/user.py`, rather than on the deferred list.

---

## 4. Verification evidence

### 4.1 The three repository scans

These are the effectiveness metrics, made executable. All three run in
[`ci.yml`](../../.github/workflows/ci.yml), which is the authoritative definition of each pattern.

| Gate | What it checks | Scope | Before | Now | Character |
| --- | --- | --- | --- | --- | --- |
| One | Credential patterns | every tracked file, the workflow included | 4 | 0 | Remediation |
| Two | Client-secret patterns | all of `frontend/`, less `node_modules/`, `build/`, `coverage/` | 0 | 0 | Regression prevention |
| Three | Browser token storage | all of `frontend/`, same three exclusions | 3 | 0 | Remediation |

Gate one flags the well-known default PostgreSQL credential pair, an inline SQL password literal, an
assigned signing-key value, and any connection URL carrying an embedded password. Its four hits sat in
the Compose environment block and in three lines of the development setup script. That last count
settles a scope question by measurement. Three of the four sat in a file the twelve findings never
name, so `scripts/setup_dev_environment.sh` had to be in scope or the metric could not reach zero.

Gate two matches `client_secret` and `paypal_secret` in either separator spelling or none, case
insensitively. Gate three matches six mechanisms: `localStorage`, `sessionStorage`, `indexedDB`,
`Storage.prototype`, `document.cookie` and `window.name`. Both cover all of `frontend/`, not only
`frontend/src/`.

**No file is exempt from gate one, and this document still describes it rather than reproducing it.**
The pattern uses one-character bracket expressions so that it matches the same text without matching
its own line, which is what removed the two exemptions it once needed. Quoting the expression here
would nonetheless make this file a hit, because gate one reads every tracked file. The workflow holds
the exact expression; [`SECURITY.md`](../../SECURITY.md) section 2.6 covers all three scans and
[`decision-log.md`](decision-log.md) sections 36 and 41.6 carry the reasoning.

Exemption is not the same as admission, and the gate now has both. The pattern matches an assignment
with or without spaces and quotes, which reaches the formatter-compliant spelling. A second reviewed
stage admits four named classes: a value read from configuration, a name denoting a policy bound or
metadata, an upper-case placeholder token, and a line carrying the reviewed marker with a reason.
`DL-208` carries the pattern's breadth and the four spellings left uncovered.

Measured on the current tree: the pattern matches **24 lines**, the allow-list leaves **0**, **8** of
the matched lines carry the reviewed-line marker, and the marker appears **10 times** in tracked
content — two of those being the workflow's own comment and its allow-list expression. Every marked
line sits under `backend/tests/`, and none in application source. The guard tests generate all four
numbers from the tree and compare them against both this file and
[`SECURITY.md`](../../SECURITY.md) section 2.6, so a stale metric fails a case; they also require
every marked line to carry a reason.

Gate three's three hits were the write, the remove and the read of the stored token, all in the
pre-fix frontend authentication service at `auth.ts:11`, `:21` and `:25`, with the key declared at
`:5`. Gate
two never had a hit, so its pipeline step prevents a regression rather than closing one.

### 4.2 Test and style baselines

A green pipeline is not on offer, and claiming one would be false. The numbers below are measured, so
that "no new failures" means something.

| Measure | Before | Now |
| --- | --- | --- |
| Tests collected under `backend/` | 0, with 3 collection errors | 738 collected, with the same 3 collection errors |
| `tests/security` result | did not exist | 738 passed, 1 warning |
| Style findings under `backend/` | 129 | 107 |
| Undefined names | 4 | 1 |

The collected figure needs the collection-error flag on the command, and
[`SECURITY.md`](../../SECURITY.md) section 2.3 carries the measurement for what happens without it:
pytest abandons the run during collection and executes nothing.

The single warning is pre-existing and outside this scope: `declarative_base()` at `models.py:5` is
the SQLAlchemy 2.0 moved-name deprecation, raised by a reference file no change here touches.

The three pre-existing test modules still fail to import, for reasons that predate this work and are
outside its scope. The four undefined names were `listings.py:18`, `subscriptions.py:54` and two
annotation sites in `paypal_service.py`, all four located in the pre-fix tree; three are gone, and the
one that remains is the out-of-scope missing datetime import, whose shipped use is the comparison at
`subscriptions.py:60`. Creating the manifest is what allowed the
pipeline to reach these steps at all, so they are running for the first time rather than newly
failing.

### 4.3 Infrastructure validation

Plan review does not run today, and it has **two** independent pre-existing blockers rather than one.
`outputs.tf` references nine resource addresses of which only two are declared in `main.tf`; the seven
absent ones are three storage buckets, two messaging topics and two functions. Separately, `main.tf:45`
reads `var.gke_num_nodes`, which `variables.tf` declares nowhere.

Both blockers predate this work and neither follows from it. Neither breaks an automated gate either,
because no workflow in this repository invokes Terraform at all. Repairing them is unrelated cleanup;
[`SECURITY.md`](../../SECURITY.md) section 2.7 carries the workaround for validating the changed
resource in the meantime.

Two checks do pass, and both were rerun after the provider work. Formatting is clean on the two changed
configuration files, with the pre-existing offender confined to `outputs.tf`. Initialisation succeeds
and selects the locked provider build under the declared constraint. Validation still reports the same
eight errors as before, all of them the two blockers above — the count is unchanged by this work, which
is the claim that matters here.

---

## 5. Design intent in the sibling specifications

The three documents under `documentation/` are read as corroborating evidence and are not modified.
Reconciling them with the delivered state is documentation work outside this scope.

### 5.1 Corroborated there

Several controls are documented design intent rather than inventions of this pass, which is worth
knowing when reviewing a threshold.

| Control | Where the specifications say so |
| --- | --- |
| SEC-04's twelve-character minimum and its four character classes | `Technical Specifications.md:596-598` |
| SEC-07's five-attempt, fifteen-minute threshold | `Technical Specifications.md:607` |
| Token-based sessions with a bounded lifetime | `Technical Specifications.md:609-612` |
| SEC-10's encrypted transport | `Technical Specifications.md:655-657`, `SRS:513` |
| SEC-12's managed secret store | `SRS:908-913`, a Secret Manager code example |
| Encryption at rest and key management | `Technical Specifications.md:651-653`, `SRS:514`, `SRS:755-758` |
| Compliance context for GDPR and CCPA | `Technical Specifications.md:670`, `SRS:517-518` |
| Application-layer role-based access control | `Technical Specifications.md:616-618`, `SRS:393`, `SRS:509`, `Software Project Proposal.md:465` |

Two claims are worth stating precisely, because the obvious citation for each does not exist.

- **Row-level security appears nowhere in the three specifications.** A search across
  `documentation/` returns no match. The SEC-11 gap therefore rests on the analysis in the brief and
  on the verifiable absence of any row-level policy in the repository, not on a document that names
  it. The role-based access control cited above is an application-layer control and a different
  thing.
- **No specification states that the client cannot complete an authenticated request.** The evidence
  is first-hand instead, and stronger for it. Five layers of import-time failure stood between the
  repository and a running process. The guard also compared a subject typed `str` against the integer
  primary key declared at `models.py:10` — pre-fix, at lines 48 and 35 of `core/security.py`, whose
  shipped equivalents are the coercion at `security.py:82` and the filter at `:83`.

### 5.2 Named there, not delivered here

Each gap below is either on the exclusion list supplied with the brief or is one of the four labelled
partial remediations. [`decision-log.md`](decision-log.md) carries both sets: section 32 holds the four
partial remediations with the gap named in each, and section 35 holds the design intent named in the
sibling specifications that this work does not deliver.
[`SECURITY.md`](../../SECURITY.md) section 4 lists the follow-ons in priority order.

| Design intent | Status here |
| --- | --- |
| Optional time-based one-time-password authentication, at `Technical Specifications.md:601-603` and `SRS:506` | Excluded by the brief |
| OAuth 2.0 authentication, at `SRS:505` | Excluded by the brief |
| A managed secret store, at `SRS:908-913` | Deferred; SEC-12 delivers custody discipline instead |
| Encryption at rest under a managed key service, at `Technical Specifications.md:651-653` | Out of scope; no finding covers it |
| Certificate-verifying database transport | Deferred; SEC-10 delivers encryption without identity verification |
| Row-level security | Deferred; SEC-11 delivers role separation only |

The specifications also disagree with themselves on one point, noted once and left alone: `SRS:891`
requires TLS 1.2 or higher for payment transactions, while `SRS:513` and
`Technical Specifications.md:656` require 1.3 or higher. Reconciling the two is documentation work
outside this scope.

Two pre-existing frontend defects are named here so neither is read as new. The navigation component
at `frontend/src/components/NavBar.tsx:3` imports a `useAuth` hook from the authentication service,
which exports only `login` and `logout`. The specifications sketch that hook at
`Technical Specifications.md:628`, importing it from a `hooks` directory the repository does not
contain. Neither the component nor the hook is in scope, and the acceptance criterion is that no
**new** failure appears.

The client-side password rule has the mirror-image problem, and it is why SEC-04 matters more than the
finding text suggests. Verified first-hand: `isValidPassword` occupies exactly one line in the whole
repository, its own declaration at `validators.ts:18`, and no registration component exists anywhere
under `frontend/src/`, although `SRS:809` calls for login and registration forms. The policy was
therefore enforced in **zero** places before SEC-04, not one.
