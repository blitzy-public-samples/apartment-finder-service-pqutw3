#!/bin/bash
#
# Fails when a secret has entered version control, or when the ignore
# policy that keeps one out has been weakened.
#
# The credentials this repository once committed cannot be un-leaked by a
# code change: removing a value from the tree leaves it in the history and
# in every existing clone, so revoking and rotating them is an operational
# step recorded in docs/security/CREDENTIAL_ROTATION.md. What this script
# does is prevent a recurrence, which is the part a pipeline can enforce.
#
# Four things are checked:
#
#   1. no path that carries a secret by convention is tracked
#   2. no tracked file carries a real credential
#   3. every path a secret could be reintroduced through is ignored
#   4. the documented example file is still committable
#
# Check 2 distinguishes a credential from documentation by its value
# rather than by its location: a connection string whose password is one
# of the documented placeholders is documentation, and one whose password
# is anything else is a committed credential. So .env.example is scanned
# like any other file, and replacing its placeholder with a real password
# fails this check.

set -Eeuo pipefail

#: Paths that carry a secret by convention. .env.example is the single
#: exception and is excluded below, because it exists to be committed.
SECRET_PATHS='(^|/)\.env($|\.)|(^|/)secrets?/|(^|/)[^/]*service-account[^/]*\.json$|(^|/)[^/]*credentials[^/]*\.json$|(^|/)id_(rsa|ed25519)|\.(pem|key|p12|pfx|jks|keystore|kubeconfig)$|(^|/)\.netrc$|(^|/)\.pgpass$'

#: A connection string carrying an inline user name and password.
DSN='(postgres(ql)?|mysql|mongodb|redis|amqp)(\+[a-z0-9_]+)?://[^[:space:]:/@"]+:[^[:space:]@"]+@'

#: Markers that make a value documentation rather than a credential.
#: The last group is the convention this repository's own pipeline uses
#: for a throwaway value: the value states that it is not a credential,
#: in either the hyphenated or the underscored spelling. A service
#: container that exists for one job and listens on loopback still has
#: to carry a working password, so the rule cannot be "no password" --
#: it is "no password that does not declare itself".
PLACEHOLDER='REPLACE_|CHANGE_?ME|[Yy]our_|YOUR_|placeholder|PLACEHOLDER|example|EXAMPLE|xxx|XXX|\$\{|\$\(|<[^>]*>|not[-_]a[-_]secret|not[-_]a[-_]real[-_]credential|not[-_]a[-_]credential|not[-_]real'

#: The placeholder signing key the setup script once wrote, matched only
#: where it is assigned as a value. The configuration module names the
#: same string in the set it refuses, and that occurrence must stay.
PLAINTEXT_KEY='(SECRET_KEY|JWT_SECRET)[[:space:]]*[=:][[:space:]]*"?your_secret_key_here'

#: A private key block, in any of its armoured forms.
PRIVATE_KEY='-----BEGIN [A-Z ]*PRIVATE KEY-----'

#: Paths a secret could be reintroduced through. Each must be ignored.
REINTRODUCTION_PATHS=(
    .env
    .env.local
    .env.production
    backend/.env
    infrastructure/docker/.env
    secrets/service-account.json
    secrets/key.json
    google-credentials.json
    service-account.json
    credentials.json
    id_rsa
    id_ed25519
    server.pem
    server.key
    cluster.kubeconfig
    .netrc
    .pgpass
)

#: Paths that must stay committable, so the ignore rules above cannot be
#: widened until they remove the project's own documentation.
REQUIRED_PATHS=(
    .env.example
    README.md
    backend/requirements.txt
)

failed=0

echo "Checking that no secret-bearing path is tracked"
tracked="$(git ls-files -z | tr '\0' '\n' \
    | grep -Ei "${SECRET_PATHS}" \
    | grep -Ev '^\.env\.example$' || true)"
if [ -n "${tracked}" ]; then
    echo "These paths carry a secret by convention and are tracked:" >&2
    echo "${tracked}" >&2
    failed=1
fi

echo "Checking that no tracked file carries a real credential"

# git grep reports each match as path:line:content, so the placeholder test
# is applied to the connection string alone rather than to the whole line.
# Applied to the line, a path carrying a placeholder token would exempt
# every match in it -- and .env.example, the one file an operator copies and
# edits, is such a path.
carried=""
while IFS= read -r match; do
    [ -n "${match}" ] || continue

    value="$(printf '%s\n' "${match}" | grep -oE "${DSN}" | head -n 1)"

    if printf '%s\n' "${value}" | grep -Eq "${PLACEHOLDER}"; then
        continue
    fi

    carried="${carried}${match}"$'\n'
done <<EOF
$(git grep -nIE "${DSN}" -- . ':(exclude)backend/tests/*' || true)
EOF

carried="${carried}$(git grep -nIE "${PLAINTEXT_KEY}" -- . \
    ':(exclude)backend/tests/*' ':(exclude)docs/*' ':(exclude)*.md' \
    || true)"
carried="${carried}$(git grep -nIE -e "${PRIVATE_KEY}" -- . || true)"
if [ -n "${carried}" ]; then
    echo "These tracked lines carry a credential:" >&2
    echo "${carried}" >&2
    failed=1
fi

echo "Checking that every reintroduction path is ignored"
for candidate in "${REINTRODUCTION_PATHS[@]}"; do
    if ! git check-ignore -q "${candidate}"; then
        echo "${candidate} is not ignored, so it can be committed." >&2
        failed=1
    fi
done

echo "Checking that every documented path is still committable"
for candidate in "${REQUIRED_PATHS[@]}"; do
    # --no-index is what makes this check answerable. Without it,
    # check-ignore skips any path present in the index, so a rule widened
    # over one of these -- each of which is tracked -- would report as not
    # ignored and the check could never fail.
    if git check-ignore -q --no-index "${candidate}"; then
        echo "${candidate} is ignored but must be tracked." >&2
        failed=1
    fi
done

if [ "${failed}" -ne 0 ]; then
    echo "The secret and ignore policy is not satisfied." >&2
    exit 1
fi

echo "The secret and ignore policy is satisfied."
