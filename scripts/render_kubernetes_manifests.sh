#!/bin/bash
set -euo pipefail

# Renders the Kubernetes manifests in infrastructure/kubernetes/ by
# substituting every ${TOKEN} they carry with the value of the environment
# variable of that name, and writes the result to standard output.
#
# Usage, from the repository root:
#
#   scripts/render_kubernetes_manifests.sh prerequisites
#   scripts/render_kubernetes_manifests.sh migration
#   scripts/render_kubernetes_manifests.sh workloads
#   scripts/render_kubernetes_manifests.sh all
#   scripts/render_kubernetes_manifests.sh admin-credential
#   scripts/render_kubernetes_manifests.sh 40-backend.yaml
#
# A group renders its files in the order listed below, so the namespace is
# created before anything placed in it. An argument ending in `.yaml` is
# taken as a file name relative to the manifest directory instead.
#
# The three release groups are applied in this order by both deployment
# paths: prerequisites, then migration run to completion, then workloads.
# The serving images therefore change only after the schema migration has
# succeeded. `all` selects exactly those three.
#
# admin-credential is outside `all` and outside both deployment paths.
# Render and apply it once per environment after the migration group, and
# again only to perform a reset; see docs/security/CREDENTIAL_ROTATION.md.
#
# The script stops with the name of the token when a token a selected file
# carries is unset or empty and carries no default below, and it stops
# again if any ${...} remains in the rendered output. Both deployment
# paths -- .github/workflows/cd.yml and scripts/deploy.sh -- render
# through this one script, so neither can drift from the manifests or from
# each other.

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
readonly REPO_ROOT
readonly MANIFEST_DIR="${REPO_ROOT}/infrastructure/kubernetes"

# Everything a workload needs in place before it starts, and which no
# serving image depends on.
readonly GROUP_PREREQUISITES=(
    "00-namespace.yaml"
    "10-service-accounts.yaml"
    "20-backend-config.yaml"
    "30-backend-secrets.yaml"
    "35-migration-secrets.yaml"
)

# The one-shot schema migration.
readonly GROUP_MIGRATION=(
    "60-migration-job.yaml"
)

# The serving workloads and the services that front them.
readonly GROUP_WORKLOADS=(
    "40-backend.yaml"
    "45-backend-hpa.yaml"
    "50-frontend.yaml"
    "55-frontend-hpa.yaml"
    "65-ingestion-cronjob.yaml"
)

# The operator step that gives the seeded administrator a credential. It is
# not part of any release, so it is absent from `all`.
readonly GROUP_ADMIN_CREDENTIAL=(
    "70-admin-credential-job.yaml"
)

# Tokens that carry a value when the environment does not set one. Each
# entry is NAME=value. A token absent from this list is required.
#
# FROM_EMAIL and ZILLOW_API_URL carry no default on purpose: every value
# that would read as an example addresses a reserved example domain, which
# backend/app/core/config.py refuses outside a local run. A default the
# application refuses does not make the render succeed, it moves the failure
# from the render to pod start, so the operator states both. The same
# applies to the origin and host lists, the PayPal client identifier and the
# two PayPal redirect URLs, none of which has a value that is right for more
# than one deployment.
readonly TOKEN_DEFAULTS=(
    "K8S_NAMESPACE=apartment-finder"
    "BACKEND_SERVICE_ACCOUNT=backend"
    "FRONTEND_SERVICE_ACCOUNT=frontend"
    "BACKEND_REPLICAS=2"
    "FRONTEND_REPLICAS=2"
    "FRONTEND_SERVICE_TYPE=ClusterIP"
    "BACKEND_ENVIRONMENT=production"
    "JWT_ISSUER=apartment-finder-service"
    "JWT_AUDIENCE=apartment-finder-web"
    "PAYPAL_MODE=live"
    "PAYPAL_API_BASE=https://api-m.paypal.com"
    "ADMIN_CREDENTIAL_RESET=false"
    "ADMIN_PROVISIONER_SERVICE_ACCOUNT=admin-provisioner"
    "MIGRATION_SERVICE_ACCOUNT=backend-migrate"
    "MIGRATION_SERVICE_ACCOUNT_ID=backend-migrate-sa"
    "BACKEND_MAX_REPLICAS=10"
    "FRONTEND_MAX_REPLICAS=6"
    "INGESTION_SCHEDULE=0 * * * *"
)

# Report the default recorded for a token, or nothing when it has none.
token_default() {
    local name="$1"
    local entry
    for entry in "${TOKEN_DEFAULTS[@]}"; do
        if [ "${entry%%=*}" = "${name}" ]; then
            printf '%s' "${entry#*=}"
            return 0
        fi
    done
    return 0
}

# Resolve a token to the value it is rendered with.
token_value() {
    local name="$1"
    local value="${!name-}"
    if [ -z "${value}" ]; then
        value="$(token_default "${name}")"
    fi
    if [ -z "${value}" ]; then
        echo "Required manifest token ${name} is not set." >&2
        return 1
    fi
    if [ "${value}" != "${value%$'\n'*}" ]; then
        echo "Manifest token ${name} carries a newline." >&2
        return 1
    fi
    printf '%s' "${value}"
}

# Escape the characters sed reads specially in a replacement.
escape_replacement() {
    printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'
}

# Collect the token names a file carries, one per line, without repeats.
tokens_in() {
    grep -o '\${[A-Za-z_][A-Za-z0-9_]*}' "$1" \
        | sed -e 's/^\${//' -e 's/}$//' \
        | sort -u
}

# Render one file to standard output.
render_file() {
    local path="$1"
    local rendered
    local name
    local value

    if [ ! -f "${path}" ]; then
        echo "Manifest ${path} does not exist." >&2
        return 1
    fi

    rendered="$(cat "${path}")"
    while read -r name; do
        [ -n "${name}" ] || continue
        value="$(token_value "${name}")"
        value="$(escape_replacement "${value}")"
        rendered="$(printf '%s\n' "${rendered}" \
            | sed -e "s|\${${name}}|${value}|g")"
    done <<EOF
$(tokens_in "${path}")
EOF

    if printf '%s\n' "${rendered}" | grep -q '\${[A-Za-z_][A-Za-z0-9_]*}'; then
        echo "Rendered ${path} still carries an unresolved token." >&2
        printf '%s\n' "${rendered}" \
            | grep -o '\${[A-Za-z_][A-Za-z0-9_]*}' >&2
        return 1
    fi

    printf '%s\n' "${rendered}"
}

# Resolve one argument to the files it selects.
files_for() {
    local selector="$1"
    case "${selector}" in
        prerequisites)
            printf '%s\n' "${GROUP_PREREQUISITES[@]}"
            ;;
        migration)
            printf '%s\n' "${GROUP_MIGRATION[@]}"
            ;;
        workloads)
            printf '%s\n' "${GROUP_WORKLOADS[@]}"
            ;;
        all)
            printf '%s\n' "${GROUP_PREREQUISITES[@]}" \
                "${GROUP_MIGRATION[@]}" "${GROUP_WORKLOADS[@]}"
            ;;
        admin-credential)
            printf '%s\n' "${GROUP_ADMIN_CREDENTIAL[@]}"
            ;;
        *.yaml)
            printf '%s\n' "${selector}"
            ;;
        *)
            echo "Unknown manifest selector ${selector}. Use" \
                "prerequisites, migration, workloads, all," \
                "admin-credential, or a <name>.yaml file in" \
                "${MANIFEST_DIR}." >&2
            return 1
            ;;
    esac
}

main() {
    local selector
    local name

    if [ "$#" -eq 0 ]; then
        echo "Usage: $0 <prerequisites|migration|workloads|all" \
            "|admin-credential|FILE.yaml>..." >&2
        return 2
    fi

    for selector in "$@"; do
        while read -r name; do
            [ -n "${name}" ] || continue
            echo "---"
            render_file "${MANIFEST_DIR}/${name}"
        done <<EOF
$(files_for "${selector}")
EOF
    done
}

main "$@"
