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
| **SEC-07** | Unrestricted authentication attempts. CWE-307. A07:2021. Medium. **Partial** | A limiter with in-memory storage applies five attempts per fifteen minutes to `POST /auth/login`, layered with an in-process counter keyed by the **exact stored identity** so a distributed attempt on one account is also bounded. The counter key is the exact value the credential query filters on, so counter identity and database identity are one value; `DL-337` carries the correction from the earlier folded key. Both credential branches perform one fixed-cost password verification, against a per-process random stand-in hash when no row matches, and the equality asserted is hasher invocation count rather than wall-clock duration. `DL-338` carries that branch. Throttled attempts are logged rather than silently dropped. **Gaps**: total request timing is not proven equal, because the absent branch skips one query (`DL-338`). And the throttle state is per-worker and lost on restart, so lockout is neither durable nor multi-replica-safe | `backend/app/main.py`, `backend/app/api/endpoints/auth.py`, `backend/app/core/config.py`, `backend/tests/security/test_login_throttle.py` |
| **SEC-08** | Information exposure through an error message. CWE-209, CWE-497. A05:2021. Medium | Four global handlers replace the placeholder comment that stood at `main.py:35` in the pre-fix tree, sharing one response envelope and a correlation identifier while full diagnostics go to the server log. Uniformity is the requirement, so the SEC-02 normalisation of the 404 into a 401 belongs to this row as well: a differential response is an account-state oracle. `DL-241` carries it. On the log side, a record factory scoped to this application folds every record to one line at creation, before propagation, and every C0 control character and the delete character are translated. `DL-339` and `DL-340` carry the placement and the character set | `backend/app/main.py`, `backend/app/core/security.py`, `backend/tests/security/test_error_handling.py` |
| **SEC-09** | Insecure default initialization of a resource. CWE-1188, CWE-798. A05:2021. High | `PAYPAL_MODE` is restricted to `sandbox` or `live`, and the service reads it from the settings class at `paypal_service.py:75` and `:306`, in place of the hardcoded literal and its manual-edit comment, which stood at `paypal_service.py:11` in the pre-fix tree. A pipeline step asserts that no client-secret pattern appears under `frontend/`; the property already held, so the step converts an accident into an invariant. The charge seam is the second half of this row. A charge authorizes only against a reference the provider confirms for the requested amount, currency and payer, and for a reusable agreement only for the plan the request names. It is recorded in a worker-local ledger that refuses a replay while the digest is retained, and `subscriptions.py:24` binds the requested plan on the call. `DL-332`, `DL-124` and `DL-201` carry these three. **Gap**: the ledger holds 4,096 digests per worker, evicts the oldest past that and is lost on restart, so replay protection is neither durable nor multi-replica-safe | `backend/app/core/config.py`, `backend/app/services/paypal_service.py`, `backend/app/api/endpoints/subscriptions.py`, `.github/workflows/ci.yml`, `backend/tests/security/test_config_guards.py` |
| **SEC-10** | Cleartext transmission to the database. CWE-319. A02:2021. High. **Partial** | The Cloud SQL instance gains `ip_configuration { ssl_mode = "ENCRYPTED_ONLY" }`, and the engine passes an environment-driven `sslmode` through `connect_args` for PostgreSQL URLs only, since SQLite raises `TypeError` on that argument. The control sits at both ends: the instance refuses unencrypted connections, and the engine requests encryption. `DL-245` carries the documented local exception for the Auth Proxy topology. The deprecated `require_ssl` argument is not used. The provider that supplies the encryption argument is part of the control: the configuration bounds it to one major line, and the generated lock is tracked with a directory hash for each of the four platforms an operator or the pipeline installs from. `DL-350` carries the lock decision. **Gap**: `require` encrypts but performs no server-identity check | `infrastructure/terraform/main.tf`, `infrastructure/terraform/.terraform.lock.hcl`, `backend/app/core/config.py`, `backend/app/db/database.py`, `infrastructure/docker/docker-compose.yml`, `.env.example`, `backend/tests/security/test_config_guards.py` |
| **SEC-11** | Execution with unnecessary privileges. CWE-250, CWE-269. A01:2021. Medium. **Partial** | The two halves reach different depths. Locally the single all-privileges account splits into an owner role used for schema work and an application role holding only connect, schema usage and table data rights. Two revokes strip the defaults `PUBLIC` holds: `CREATE` on the schema, and `CONNECT` with `TEMPORARY` on the database. The batch then reads the **effective** access lists and raises rather than trusting the statements it just issued, substituting the default list where the stored one is null. `DL-36`, `DL-353` and `DL-354` carry those three. On Cloud SQL, Terraform declares a `google_sql_user` whose password comes from a variable rather than a literal, which separates the account from the instance admin and restricts nothing; the out-of-band statements in `SECURITY.md` section 3.2 are what narrow it, and `DL-293` carries the declaration. **Gaps**: the cloud account stays elevated until an operator runs the statements `SECURITY.md` section 3.2 carries, schema `USAGE` is deliberately left with `PUBLIC`, and nothing here delivers row-level security | `scripts/setup_dev_environment.sh`, `infrastructure/terraform/main.tf`, `infrastructure/terraform/variables.tf`, `infrastructure/terraform/.terraform.lock.hcl`, `.gitignore`, `SECURITY.md`, `backend/tests/security/test_config_guards.py` |
| **SEC-12** | Insufficiently protected credentials in custody. CWE-522. A05:2021. Medium. **Partial** | Exclusion rules and a template carrying no real secret keep secrets out of version control. Every secret and deployment-specific identifier in that template is an angle-bracket placeholder; the remaining lines document non-secret code defaults and required choices. `SECRET_KEY` gains a `min_length=32` floor grounded in RFC 7518 section 3.2, the three settings that raised `AttributeError` are declared, and a pipeline secret scan enforces the discipline on every run. Provisioning carries the same custody. The setup script generates values instead of emitting literals and creates the file under `umask 077`, per `DL-40` and `DL-181`. Terraform takes the database password from an `ephemeral`, `sensitive` variable with no default through the write-only `password_wo` argument, so the value reaches neither state nor a plan file. Build context carries the same custody: three context-local ignore files keep the environment file, the `secrets/` directory, certificates, keys, credential JSON, virtual environments, dependency trees, caches and coverage out of every image layer, which `.gitignore` cannot do for an untracked file. The variable's own description is a custody control too: it names the environment variable and a gitignored variable file as the two supported channels and prohibits the command-line flag. `DL-369` carries that wording. The generated environment file is published with a link call that fails when the destination exists in any form, so a directory or symlink appearing at that path cannot absorb the file or be written through, and no check precedes the act. **Gaps**: no managed secret store, deployment still authenticates with a long-lived credential, and both container definitions still copy their whole context rather than an allow-list | `.gitignore`, `.env.example`, `SECURITY.md`, `.dockerignore`, `backend/.dockerignore`, `frontend/.dockerignore`, `infrastructure/docker/Dockerfile.backend`, `infrastructure/docker/Dockerfile.frontend`, `infrastructure/docker/docker-compose.yml`, `backend/app/core/config.py`, `.github/workflows/ci.yml`, `scripts/setup_dev_environment.sh`, `infrastructure/terraform/main.tf`, `infrastructure/terraform/variables.tf`, `infrastructure/terraform/.terraform.lock.hcl`, `backend/tests/security/test_config_guards.py` |
| **Prerequisite** | No dependency manifest, so the dependency surface had never been enumerated. CWE-1104. A06:2021 | `backend/requirements.txt` pins nineteen packages exactly, fourteen runtime and five for test and audit tooling. Two pins are load-bearing beyond version hygiene: `bcrypt==4.3.0` prevents a passlib capability probe that would break every password hash, and omitting a multipart parser keeps six advisories that cannot be patched on this runtime out of the closure | `backend/requirements.txt`, `.github/workflows/ci.yml` |

---

## 2. Direction B — file to control to finding

One row per delivered path, forty-seven in all, grouped by directory: the thirty-nine of the planned
change set plus the eight delivered outside it, which section 3.4 names with their departure
recorded. **Mode** is `CREATE`, `UPDATE`
or `REFERENCE`, where a reference file is read as an authority and deliberately left unchanged, and a
mode reading *delivered* differs from the plan. Controls are named, not re-explained; section 1 holds
the mechanism.

### 2.1 Repository root

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `.gitignore` | CREATE | Excludes the environment file, the secrets directory, certificates, keys and credential JSON, plus Terraform state and variable files. `password_wo` from an `ephemeral` variable keeps the database password out of both state and plan, so these two exclusions stand on the variable file being the conventional home for an operator-supplied value and on state recording other resource attributes | SEC-01, SEC-11, SEC-12 |
| `.env.example` | CREATE | Documents every required variable by name, shape and purpose, including the JSON-array form the origin list expects. Secrets and deployment-specific identifiers appear as angle-bracket placeholders; the rest are documented non-secret defaults and required choices, so no line carries a real credential. Carries both contracts: the backend settings, and a final section naming the two frontend build variables the client bundle embeds | SEC-01, SEC-03, SEC-10, SEC-12 |
| `.dockerignore` | CREATE | The root build context, and the widest of the three ignore files: it also excludes both sub-context caches, virtual environments, dependency trees and the frontend build and coverage output. Excludes the environment file and its temporary form, the `secrets/` directory, certificates, keys and credential JSON, so a broad `COPY . .` cannot carry an untracked secret into an image layer | SEC-12 |
| `backend/.dockerignore` | CREATE | The context `Dockerfile.backend` builds from, whose `COPY . .` would otherwise carry the whole backend tree. Excludes the same secret-bearing paths, plus the Python caches, egg metadata, virtual environments and coverage output | SEC-12 |
| `frontend/.dockerignore` | CREATE | The context `Dockerfile.frontend` builds from, whose `COPY . .` would otherwise carry the whole frontend tree. Excludes the same secret-bearing paths, plus `node_modules/`, `build/` and `coverage/` | SEC-12 |
| `SECURITY.md` | CREATE | Operator-facing custody procedure, verification commands, residual-risk register and the deferred follow-ons. Section 3.2 also carries the out-of-band `REVOKE` and `GRANT` statements that reduce the Cloud application account, which no provider resource can express | SEC-11, SEC-12 |

### 2.2 Backend application

| File | Mode | Control it carries | Closes |
| --- | --- | --- | --- |
| `backend/requirements.txt` | CREATE | Nineteen exact pins, including the availability-critical `bcrypt==4.3.0`; unblocks `Dockerfile.backend` and the pipeline install step, both of which already referenced this file | Prerequisite (CWE-1104) |
| `backend/app/core/config.py` | UPDATE | Validated security settings: the required origin allow-list, the payment-mode domain, the transport mode, the cookie flag, the limiter thresholds, the signing-key floor and the three settings that previously raised `AttributeError` | SEC-03, SEC-06, SEC-07, SEC-09, SEC-10, SEC-12 |
| `backend/app/main.py` | UPDATE | Explicit method and header lists on the cross-origin middleware, the limiter registration and its exceeded handler, the four global exception handlers, and the record factory that folds every application record to one line before propagation. Also corrects the import source for `Base`, which is boot-blocker layer four | SEC-03, SEC-07, SEC-08 |
| `backend/app/core/security.py` | UPDATE | Integer coercion of the subject inside a 401 guard, the uniform 401 with `WWW-Authenticate: Bearer`, the `iat` claim, and the cookie-before-header read | SEC-02, SEC-06, SEC-08 |
| `backend/app/api/endpoints/auth.py` | UPDATE | Mints the subject as the user identifier, binds `UserCreate` and `UserLogin` so the password reaches a validating allow-list before hashing, sets and clears the session cookie, adds `POST /auth/logout`, and applies the login limit keyed on the exact stored identity. Both credential branches perform one fixed-cost verification, against a per-process random stand-in hash when no row matches. Also supplies the non-null `created_at` without which registration always failed | SEC-02, SEC-04, SEC-05, SEC-06, SEC-07 |
| `backend/app/api/endpoints/listings.py` | UPDATE | The model import at `:7` extends to include `User`, resolving the annotation at `:18` and clearing boot-blocker layer two. The same signature binds `ListingCreate`, so the allow-list reaches the expansion at `:21`; see the SEC-05 row in section 1. The route answers a sanitized 500 and persists nothing, for the schema reasons section 3.4 records | Enabling repair, SEC-05 |
| `backend/app/schema/user.py` | UPDATE | Strict create and login models, the password policy with its byte ceiling, the integer identifier, and removal of the password-hash field from the outbound model | SEC-02, SEC-04, SEC-05 |
| `backend/app/schema/filter.py` | UPDATE | Strict allow-list of writable filter fields, applied to the nested criteria as well | SEC-05 |
| `backend/app/schema/listing.py` | UPDATE | Strict allow-list of writable listing fields, the control for the mass-assignment site, with a finiteness check on each declared float so a non-finite literal is refused at the boundary rather than stored | SEC-05 |
| `backend/app/schema/subscription.py` | CREATE | Supplies the create and response models the subscription endpoint already imported from a module that did not exist. Boot-blocker layer one | SEC-05 |
| `backend/app/db/database.py` | UPDATE | Passes the transport mode through `connect_args`, conditionally and only for PostgreSQL URLs | SEC-10 |
| `backend/app/services/paypal_service.py` | UPDATE | Reads the payment environment from the validated setting, and carries the charge verifier: a reference is claimed in a local ledger, resolved through the provider under a bounded transport, bound to state, amount, currency, payer and plan, then recorded in a bounded worker-local ledger. A replay is refused while the digest is retained, and not after eviction or a restart. Also adds the missing typing import for both annotation sites and the async wrapper the subscription endpoint calls, clearing boot-blocker layers two and three | SEC-09 |
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
| `backend/tests/security/test_config_guards.py` | CREATE | Asserts the payment-mode domain, the signing-key length floor, and that the transport argument is applied for PostgreSQL and withheld for SQLite. It drives the charge seam and the subscription route through their production paths, in both the authorizing and the refusing direction. It asserts that a reference retained in the ledger authorizes no second charge, which is the bound that ledger's 4,096-digest capacity and per-worker lifetime allow. It holds the privilege split by reading the shipped statements: the granted set compared whole, both `PUBLIC` revokes present, no broad privilege conferred, and no role password in a process argument list. It also asserts the batch's own effective-access verification is present, which `DL-355` returns to the suite separately. It executes the provisioning publish against a destination planted after the source exists, in three forms. It reads the pipeline's own expressions and executes both gates against planted controls. And it asserts the build definitions are consumable: each named image definition exists, no declared value interpolates to empty, the backend receives every required setting, and the exposed, published and probed ports agree | SEC-01, SEC-09, SEC-10, SEC-11, SEC-12 |
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
| `infrastructure/docker/Dockerfile.backend` | **UPDATE, delivered** | Places the build context where the application's own package path resolves and starts the process above it, so the image runs the module the application declares rather than one that does not exist, and exposes the port the definition publishes. Planned outside the map; see section 3.4 | SEC-12 |
| `infrastructure/docker/docker-compose.yml` | UPDATE | Environment indirection in the fail-closed `${VAR:?message}` form for every build argument and every no-default setting, the corrected secret variable name, the complete backend settings contract, and the documented local transport exception for the Auth Proxy topology. Each service names the image definition that exists relative to its context, and each healthcheck names a program its own base image carries | SEC-01, SEC-10, SEC-12 |
| `infrastructure/terraform/main.tf` | UPDATE | The encryption-only IP configuration on the Cloud SQL instance, a separate application database account whose password reaches neither state nor a plan file, and the bounded provider and command-line ranges that pair with the tracked lock. It carries no privilege restriction, which is a provider limit rather than an omission; `DL-350` and `DL-368` carry both | SEC-10, SEC-11, SEC-12 |
| `infrastructure/terraform/.terraform.lock.hcl` | **CREATE, delivered** | The provider selection itself: one directory hash for each of the four platforms an operator or the pipeline installs from, the registry checksum set, and the constraint the configuration declared when it was generated. A range admits many builds; this file chooses one. Planned outside the map; see section 3.4 | SEC-10, SEC-11, SEC-12 |
| `infrastructure/terraform/variables.tf` | UPDATE | The application account's name, its write-only password and the counter that reapplies a rotation. Each one is read by `main.tf`; the configuration declares no variable it never reads. The password variable's description names the two supported input channels and prohibits the command-line flag that would expose the value in the process arguments and in shell history | SEC-11, SEC-12 |
| `scripts/setup_dev_environment.sh` | UPDATE | Generated rather than literal credentials, published with a link that fails when anything already stands at the destination, and the owner plus application role split that replaces the unrestricted grant. Both default `PUBLIC` privilege sets are revoked, and the batch closes by reading the effective access lists and raising if they disagree. Three of the four original credential-scan hits were in this file | SEC-01, SEC-11, SEC-12 |

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

---

## 3. Coverage reconciliation

### 3.1 The arithmetic

The table below is the **planned** map. Delivery departs from it on two paths and adds nine; section
3.4 carries every departure, and `DL-391` carries the decision behind the delivered arithmetic.

| Mode | Count | Where they sit |
| --- | --- | --- |
| CREATE | 16 | 3 at the repository root, 11 under `backend/`, 2 under `documentation/security/` |
| UPDATE | 18 | 10 under `backend/`, 3 under `frontend/`, 3 under `infrastructure/`, 1 under `scripts/`, 1 under `.github/` |
| REFERENCE | 5 | 4 under `backend/`, 1 under `frontend/` |
| DELETE | 0 | See section 3.2 |
| **Total** | **39** | Each has its own row in section 2, which carries 48 |

**Coverage is stated as measured, not asserted.** An edge-set comparison extracted from the two
sections reports **83 edges in Direction A and 83 non-exempt edges in Direction B, with an empty
difference in both directions**. It also reports **5 exempt edges across the 6 declared-asymmetric
rows** below, and **48 unique paths in 48 rows, at 20 CREATE, 25 UPDATE and 3 REFERENCE**. `DL-395`
carries the decision to state the claim this way, and `DL-403` the row split that made those two
counts equal.

What that measurement covers: every one of `SEC-01` through `SEC-12` has at least one file in section
1, and every file in section 2 traces to a finding, to the dependency prerequisite, to an enabling
repair, or to Rule 1. No section-1 claimant is missing the finding from its section-2 row, and no
section-2 row carries a finding its section-1 claimant list omits.

Six rows are deliberately asymmetric, and a cross-check has to allow for them. Three REFERENCE rows
read `Authority for` and the harness row reads `Verification for`; those four files supply an authority
or the scaffolding the assertions run on, and none carries a control. The two security documents carry
a Rule 1 obligation rather than a finding, as section 2.7 states. All six appear in section 2 against
findings whose section-1 claimant lists do not name them. Every other row is symmetric, the eight
regression-test files, `filters.py` and `subscriptions.py` included; `DL-390` carries the reconciliation
that made the last three of them so.

Version control settles the delivered mode of every row. Measured against the last pre-work commit,
each CREATE is absent there, each UPDATE differs from it, and three of the five paths planned as
REFERENCE are byte-identical to it. Two carry controls instead: `backend/app/api/endpoints/filters.py`
carries a SEC-05 control and `backend/app/api/endpoints/subscriptions.py` binds the requested plan on
the charge call, so section 2 records both as delivered updates. Nine further paths the map never
listed carry a control: the three build-context ignore files, both image definitions, the provider
lock, both frontend schema declarations, and the listing card. Section 3.4 states every departure and records what else
the branch touches.

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

**Delivery departs from the planned classification on ten paths, and the table below carries every
one.** Across the 39 planned paths: 16 created, **20 updated, 3 references left byte-identical**, no
deletions — the two differences being `backend/app/api/endpoints/filters.py` and
`backend/app/api/endpoints/subscriptions.py`, both planned REFERENCE and both delivered UPDATE.

**Nine further paths are delivered outside the map**: the three build-context ignore files, the
Terraform provider lock, both image definitions, both frontend schema declarations, and the listing
card. Four of the nine are new files and five are modifications, measured against the last pre-work
commit. Delivered totals are therefore **20 created, 25 updated, 3 byte-identical references, 48
paths**, which is what
the edge-set comparison in section 3.1 recomputes from this file. `DL-391` carries the decision.

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

Measured on the current tree: **21 lines match the pattern, all 21 are admitted, and the gate reports
0.** The marker sits on four test-fixture lines, all under `backend/tests/`, and on no line of
application source. The guard tests pin that count and require every marked line to carry a reason.

Gate three's three hits were the write, the remove and the read of the stored token, all in the
pre-fix frontend authentication service at `auth.ts:11`, `:21` and `:25`, with the key declared at
`:5`. Gate
two never had a hit, so its pipeline step prevents a regression rather than closing one.

### 4.2 Test and style baselines

A green pipeline is not on offer, and claiming one would be false. The numbers below are measured, so
that "no new failures" means something.

| Measure | Before | Now |
| --- | --- | --- |
| Tests collected under `backend/` | 0, with 3 collection errors | 689 collected, with the same 3 collection errors |
| `tests/security` result | did not exist | 689 passed, 1 warning |
| Style findings under `backend/` | 129 | 108 |
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
