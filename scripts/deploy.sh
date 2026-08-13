#!/bin/bash
#
# Release the verified images, run migrations, roll out the Kubernetes
# workloads, and optionally deploy the Cloud Function.
#
# Run `scripts/deploy.sh --help` for every input and its accepted form.

# Abort on any failing command, on any unset variable and on any failure
# within a pipeline, and let the ERR trap below reach every function.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Every path this script reads is resolved against the repository root,
# not against the directory the script was invoked from.
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT

# Deployments this script publishes, in the order it publishes them. The
# container inside each one carries the same name, and so does the image
# repository it is published under.
readonly RELEASE_WORKLOADS=("backend" "frontend")

# Image definition per workload, relative to REPO_ROOT.
declare -A WORKLOAD_DOCKERFILE=(
    ["backend"]="infrastructure/docker/Dockerfile.backend"
    ["frontend"]="infrastructure/docker/Dockerfile.frontend"
)
readonly WORKLOAD_DOCKERFILE

# Build context per workload, relative to REPO_ROOT. Each one is the
# context infrastructure/docker/docker-compose.yml builds that image
# from.
declare -A WORKLOAD_CONTEXT=(
    ["backend"]="backend"
    ["frontend"]="frontend"
)
readonly WORKLOAD_CONTEXT

# Build arguments per workload: the space-separated names each image's
# definition declares with ARG and this script passes with --build-arg.
# The backend declares none. The frontend declares two, and its bundler
# inlines both into the published bundle, so both are public values and
# neither is a credential. .github/workflows/cd.yml passes the same two.
#
# REACT_APP_PAYPAL_CLIENT_ID carries the same value as the PAYPAL_CLIENT_ID
# render token below, so the bundle and the backend configuration name one
# PayPal application. It is derived rather than supplied, so the two cannot
# be set to different applications.
declare -A WORKLOAD_BUILD_ARGUMENTS=(
    ["backend"]=""
    ["frontend"]="REACT_APP_API_BASE_URL REACT_APP_PAYPAL_CLIENT_ID"
)
readonly WORKLOAD_BUILD_ARGUMENTS

# Cloud Function contract. Every value here matches
# infrastructure/terraform/main.tf, which owns the function and its
# invoker binding. CLOUD_FUNCTION_RUNTIME is pinned and is not advanced
# here; see deploy_cloud_function below.
#
# The source object is deliberately not named here. Terraform names it
# after the archive's content digest, so the name changes whenever the
# bytes do and cannot be restated as a constant without the two drifting
# apart. It arrives as CLOUD_FUNCTION_SOURCE_OBJECT with its digest in
# CLOUD_FUNCTION_SOURCE_MD5, both read from that configuration's outputs
# of the same names.
readonly CLOUD_FUNCTION_NAME="apartment-finder-probe"
readonly CLOUD_FUNCTION_ENTRY_POINT="hello_world"
readonly CLOUD_FUNCTION_RUNTIME="python39"
readonly CLOUD_FUNCTION_SOURCE_BUCKET_SUFFIX="-static-assets"

# Bounds every step of the release carries.
readonly RENDER="${REPO_ROOT}/scripts/render_kubernetes_manifests.sh"

# Bounds every kubectl call that talks to the API server, so a step
# cannot hang against an unreachable control plane.
readonly KUBECTL_REQUEST_TIMEOUT="60s"

# Shared rate-limit store. RATE_LIMIT_SETTING is the setting the application
# reads, the Secret Manager secret_id Terraform creates, and the key inside
# the Kubernetes secret; RATE_LIMIT_STORE_SECRET is that secret's name, and
# it is what infrastructure/kubernetes/40-backend.yaml references. The same
# two names are used by .github/workflows/cd.yml.
readonly RATE_LIMIT_SETTING="RATE_LIMIT_STORAGE_URI"
readonly RATE_LIMIT_STORE_SECRET="backend-rate-limit-store"

# Manifest tokens the operator supplies rather than this script deriving
# them, split by whether the renderer carries a default for the token. The
# renderer remains the authority for which tokens a manifest requires --
# assert_manifest_tokens below asks it rather than restating its list -- and
# these arrays exist so that every operator value is re-exported, so a value
# set in the caller's shell without `export` still reaches it, and so the
# usage text is printed from the same names the release reads.
#
# The renderer defaults nothing here, so each one must carry a value:
readonly REQUIRED_RENDER_TOKENS=(
    "BACKEND_ALLOWED_ORIGINS"
    "BACKEND_ALLOWED_HOSTS"
    "BACKEND_GCP_SERVICE_ACCOUNT_EMAIL"
    "PAYPAL_CLIENT_ID"
    "PAYPAL_RETURN_URL"
    "PAYPAL_CANCEL_URL"
    "ZILLOW_API_URL"
    "FROM_EMAIL"
)

# Required only while PROVISION_ADMIN_CREDENTIAL is "true", because the only
# manifest carrying it is the administrator-credential Job, which no release
# renders otherwise:
readonly ADMIN_CREDENTIAL_RENDER_TOKENS=(
    "ADMIN_PROVISIONER_GCP_SERVICE_ACCOUNT_EMAIL"
)

# Accepted, and defaulted by the renderer when absent:
readonly DEFAULTED_RENDER_TOKENS=(
    "BACKEND_ENVIRONMENT"
    "PAYPAL_MODE"
    "PAYPAL_API_BASE"
    "BACKEND_SERVICE_ACCOUNT"
    "FRONTEND_SERVICE_ACCOUNT"
    "MIGRATION_SERVICE_ACCOUNT"
    "MIGRATION_SERVICE_ACCOUNT_ID"
    "ADMIN_PROVISIONER_SERVICE_ACCOUNT"
)

readonly OPERATOR_RENDER_TOKENS=(
    "${REQUIRED_RENDER_TOKENS[@]}"
    "${ADMIN_CREDENTIAL_RENDER_TOKENS[@]}"
    "${DEFAULTED_RENDER_TOKENS[@]}"
)

# Local port the readiness probe forwards to, and the bounds every probe
# carries so a forward that never answers cannot hold the release open.
readonly HEALTH_PORT="8000"
readonly CURL_CONNECT_TIMEOUT="5"
readonly CURL_MAX_TIME="15"

readonly ROLLOUT_TIMEOUT="10m"

# How long a one-shot Job is waited on. The migration Job declares the same
# figure as activeDeadlineSeconds, so the Job stops itself at the moment this
# wait gives up rather than continuing to hold the schema open behind a
# release that has already been reported as failed.
readonly MIGRATION_TIMEOUT="15m"
readonly COMMAND_TIMEOUT_SECONDS=1800

# Accepted form of each input, applied to the whole value.
readonly PROJECT_ID_PATTERN='^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
readonly CLUSTER_NAME_PATTERN='^[a-z]([-a-z0-9]{0,38}[a-z0-9])?$'
readonly REGION_PATTERN='^[a-z]+-[a-z]+[0-9]$'
readonly NAMESPACE_PATTERN='^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'
readonly REPOSITORY_PATTERN='^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$'
readonly IMAGE_TAG_PATTERN='^[A-Za-z0-9_][A-Za-z0-9._-]{0,126}$'
readonly DIGEST_PATTERN='^sha256:[0-9a-f]{64}$'

# Accepted form of the function's source object and of its digest. The
# object name has to carry a 32-character hex content digest, which is what
# makes it address the bytes rather than label a location that can be
# overwritten. The digest is the base64 MD5 that gcloud reports as
# md5_hash and that Terraform exposes as md5hash, so the two are compared
# in one encoding without re-encoding either.
readonly FUNCTION_OBJECT_PATTERN='^function-source-[0-9a-f]{32}\.zip$'
readonly FUNCTION_MD5_PATTERN='^[A-Za-z0-9+/]{22}==$'

# Inputs, each read from the environment and validated by read_inputs.
GCP_PROJECT_ID="${GCP_PROJECT_ID:-}"
GKE_CLUSTER="${GKE_CLUSTER:-}"
GKE_REGION="${GKE_REGION:-}"
K8S_NAMESPACE="${K8S_NAMESPACE:-}"
VERSION="${VERSION:-}"
ARTIFACT_REGISTRY_REPOSITORY="${ARTIFACT_REGISTRY_REPOSITORY:-apartment-finder}"
CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED="${CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED:-false}"
CLOUD_FUNCTION_SOURCE_OBJECT="${CLOUD_FUNCTION_SOURCE_OBJECT:-}"
CLOUD_FUNCTION_SOURCE_MD5="${CLOUD_FUNCTION_SOURCE_MD5:-}"

# References built from the inputs by build_references.
REGISTRY_HOST=""
IMAGE_PREFIX=""
EXPECTED_CONTEXT=""
FUNCTION_SOURCE=""

# Kubeconfig this run writes its one context into, removed by cleanup.
KUBECONFIG_FILE=""

# Process identifier of the readiness probe's port forward, set by
# probe_health and closed by cleanup. It is declared at this scope, and not
# inside probe_health, because the EXIT trap runs after that function has
# returned: a value local to it would be out of scope by then, and reading an
# unset name under `set -u` would abort the trap and leave the kubeconfig on
# disk.
HEALTH_FORWARD_PID=""

# Digest-pinned image published per workload.
declare -A PUBLISHED_IMAGE=()

usage() {
    cat <<'USAGE'
Usage: scripts/deploy.sh

Publishes the frontend and backend images, applies the Alembic
revisions, rolls the new images out and verifies what is running. Takes
no arguments: every input is an environment variable.

Required:
  GCP_PROJECT_ID   Google Cloud project the cluster and registry live in.
  GKE_CLUSTER      Name of the target GKE cluster.
  GKE_REGION       Region the cluster is in. The cluster is regional, so
                   this is a region such as us-central1, not a zone.
  K8S_NAMESPACE    Namespace holding the frontend and backend Deployments.
  VERSION          Image tag for this release. It must name no image that
                   has already been published: a reused tag is refused.
  REACT_APP_API_BASE_URL
                   Address the browser bundle calls the API at. Inlined
                   into the bundle at build time, so it is public.
  PAYPAL_CLIENT_ID Browser client identifier for hosted checkout. Inlined
                   into the bundle as REACT_APP_PAYPAL_CLIENT_ID and also
                   rendered into the backend configuration, so one value
                   names one PayPal application on both sides. The PayPal
                   secret is never a build argument.

USAGE

    # Printed from the arrays the release itself reads, so this contract
    # cannot fall behind the values that are validated. The three lists
    # below are the manifest tokens; every other input is prose above and
    # below, because each one carries its own explanation.
    printf '\n%s\n' "Required, and read when the manifests are rendered:"
    printf '  %s\n' "${REQUIRED_RENDER_TOKENS[@]}"
    printf '%s\n' \
        "                   Every one is refused empty, before any" \
        "                   credential is acquired. PAYPAL_CLIENT_ID is" \
        "                   the same value as the build argument above."

    printf '\n%s\n' \
        "Required only when PROVISION_ADMIN_CREDENTIAL is \"true\":"
    printf '  %s\n' "${ADMIN_CREDENTIAL_RENDER_TOKENS[@]}"
    printf '%s\n' \
        "                   The Google identity the administrator" \
        "                   credential Job runs as."

    printf '\n%s\n' "Accepted, each defaulted by the manifest renderer:"
    printf '  %s\n' "${DEFAULTED_RENDER_TOKENS[@]}"
    printf '%s\n' \
        "                   scripts/render_kubernetes_manifests.sh" \
        "                   records the default each one takes."

    cat <<'USAGE'

Optional:
  ARTIFACT_REGISTRY_REPOSITORY   Artifact Registry Docker repository the
                                 images are published to.
                                 Default: apartment-finder
  CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED
                                 "true" runs the Cloud Function step.
                                 Default: false, which reports the step
                                 as blocked and performs it not at all.
  PROVISION_ADMIN_CREDENTIAL     "true" applies the administrator
                                 credential Job. Default: false.
  ADMIN_CREDENTIAL_RESET         "true" replaces a credential already in
                                 place. Default: false.

Required only when CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED is "true", and
read from the Terraform outputs of the same names:
  CLOUD_FUNCTION_SOURCE_OBJECT   Name of the source archive object, which
                                 carries the archive's content digest.
  CLOUD_FUNCTION_SOURCE_MD5      Base64 MD5 of that object. The digest in
                                 the bucket must match it or the function
                                 step refuses to deploy.

Requires gcloud, kubectl, docker, jq and timeout on PATH, an active
Google Cloud credential, and bash 4 or newer.
USAGE
}

report_failure() {
    local status="$1"
    local line="$2"

    echo "The release failed at line ${line} with status ${status}." >&2
    echo "Nothing after that line ran." >&2
}

# The one EXIT handler this script installs. It closes the readiness
# probe's port forward if one was started and removes the private
# kubeconfig, so both happen on every exit path -- success, failure and
# interruption alike. No other function replaces it: a second definition
# would take effect globally and silently drop whichever teardown the
# first one owned.
cleanup() {
    # shellcheck disable=SC2317
    if [ -n "${HEALTH_FORWARD_PID}" ]; then
        # shellcheck disable=SC2317
        if kill "${HEALTH_FORWARD_PID}" 2>/dev/null; then
            # shellcheck disable=SC2317
            echo "closed the port forward"
        fi
        # shellcheck disable=SC2317
        HEALTH_FORWARD_PID=""
    fi

    # shellcheck disable=SC2317
    if [ -n "${KUBECONFIG_FILE}" ] && [ -e "${KUBECONFIG_FILE}" ]; then
        # shellcheck disable=SC2317
        rm -f "${KUBECONFIG_FILE}"
    fi
}

trap 'report_failure "$?" "${LINENO}"' ERR
trap cleanup EXIT

parse_arguments() {
    if [ "$#" -eq 1 ] && { [ "$1" = "-h" ] || [ "$1" = "--help" ]; }; then
        usage
        exit 0
    fi

    if [ "$#" -ne 0 ]; then
        echo "This script accepts no arguments. Every input is read from" \
            "the environment. Received: $*" >&2
        usage >&2
        exit 2
    fi
}

account_reference() {
    local value="$1"

    # A stable, non-reversible reference: the same identity always yields
    # the same twelve characters, so a log records which account a run used
    # without recording the address itself. Either digest tool is accepted
    # because a deployment host is not guaranteed to carry both.
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "${value}" | sha256sum | cut -c1-12
    else
        printf '%s' "${value}" | openssl dgst -sha256 -r | cut -c1-12
    fi
}

check_tools() {
    local tool

    if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
        echo "This script requires bash 4 or newer, and found" \
            "${BASH_VERSION}." >&2
        exit 1
    fi

    for tool in gcloud kubectl docker jq timeout; do
        if ! command -v "${tool}" > /dev/null 2>&1; then
            echo "${tool} is not installed or is not on PATH." >&2
            exit 1
        fi
    done
}

# Require one input and check its whole value against a pattern. The
# value is matched by the shell rather than by a line-oriented tool, so a
# value carrying a newline is rejected rather than partly matched.
require_input() {
    local name="$1"
    local pattern="$2"
    local value="${!name}"

    if [ -z "${value}" ]; then
        echo "Required environment variable ${name} is not set." >&2
        echo "Run ${BASH_SOURCE[0]} --help for every input." >&2
        exit 1
    fi

    if ! [[ ${value} =~ ${pattern} ]]; then
        echo "${name} carries a value this script does not accept." >&2
        echo "Accepted form: ${pattern}" >&2
        exit 1
    fi
}

read_inputs() {
    require_input GCP_PROJECT_ID "${PROJECT_ID_PATTERN}"
    require_input GKE_CLUSTER "${CLUSTER_NAME_PATTERN}"
    require_input GKE_REGION "${REGION_PATTERN}"
    require_input K8S_NAMESPACE "${NAMESPACE_PATTERN}"
    require_input VERSION "${IMAGE_TAG_PATTERN}"
    require_input ARTIFACT_REGISTRY_REPOSITORY "${REPOSITORY_PATTERN}"

    case "${CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED}" in
        true | false) ;;
        *)
            echo "CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED accepts \"true\"" \
                "or \"false\" and carries" \
                "\"${CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED}\"." >&2
            exit 1
            ;;
    esac

    # Required only when the function step runs, so a release that leaves
    # the function alone needs neither value and cannot be blocked for
    # want of an output that Terraform reports as null while the function
    # is unauthorized.
    if [ "${CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED}" = "true" ]; then
        require_input CLOUD_FUNCTION_SOURCE_OBJECT \
            "${FUNCTION_OBJECT_PATTERN}"
        require_input CLOUD_FUNCTION_SOURCE_MD5 "${FUNCTION_MD5_PATTERN}"
    fi

    read_build_arguments
}

# Resolve the frontend build arguments and require each one to carry a
# value. Both are inlined into the published bundle, so an empty one
# produces an image that builds and then cannot reach the API or open
# hosted checkout -- a failure that reaches an end user rather than this
# script. docker accepts an empty --build-arg without complaint, so the
# check has to happen here.
read_build_arguments() {
    local workload
    local name
    local value
    local -a names

    : "${REACT_APP_PAYPAL_CLIENT_ID:=${PAYPAL_CLIENT_ID-}}"

    for workload in "${RELEASE_WORKLOADS[@]}"; do
        # The names are read into an array through a quoted here-string, so
        # the table is split on whitespace without any expansion being left
        # unquoted, and a workload declaring none yields an empty array
        # rather than one empty name.
        names=()
        read -r -a names <<< "${WORKLOAD_BUILD_ARGUMENTS[${workload}]}"
        if [ "${#names[@]}" -eq 0 ]; then
            continue
        fi

        for name in "${names[@]}"; do
            value="${!name-}"
            if [ -z "${value}" ]; then
                echo "${name} is required to build the ${workload} image" \
                    "and is not set." >&2
                echo "Both frontend build values are public: set" \
                    "REACT_APP_API_BASE_URL, and PAYPAL_CLIENT_ID for the" \
                    "browser client identifier. The PayPal secret is" \
                    "never a build argument." >&2
                exit 1
            fi
        done
    done
}

build_references() {
    REGISTRY_HOST="${GKE_REGION}-docker.pkg.dev"
    readonly REGISTRY_HOST

    IMAGE_PREFIX="${REGISTRY_HOST}/${GCP_PROJECT_ID}"
    IMAGE_PREFIX="${IMAGE_PREFIX}/${ARTIFACT_REGISTRY_REPOSITORY}"
    readonly IMAGE_PREFIX

    EXPECTED_CONTEXT="gke_${GCP_PROJECT_ID}_${GKE_REGION}_${GKE_CLUSTER}"
    readonly EXPECTED_CONTEXT

    # Left empty when no source object was named, which read_inputs allows
    # only while the function step is not authorized and therefore never
    # reads this value.
    if [ -n "${CLOUD_FUNCTION_SOURCE_OBJECT}" ]; then
        FUNCTION_SOURCE="gs://${GCP_PROJECT_ID}"
        FUNCTION_SOURCE="${FUNCTION_SOURCE}${CLOUD_FUNCTION_SOURCE_BUCKET_SUFFIX}"
        FUNCTION_SOURCE="${FUNCTION_SOURCE}/${CLOUD_FUNCTION_SOURCE_OBJECT}"
    fi
    readonly FUNCTION_SOURCE

    export_render_tokens
}

# The manifest renderer substitutes these names and stops naming any one
# still unset, so they are exported once here and refreshed with the
# published digests before the serving manifests are rendered.
export_render_tokens() {
    local token

    export GCP_PROJECT_ID
    export K8S_NAMESPACE
    export IMAGE_TAG="${VERSION}"

    for token in "${OPERATOR_RENDER_TOKENS[@]}"; do
        if [ -n "${!token-}" ]; then
            export "${token?}"
        fi
    done

    if [ -n "${PUBLISHED_IMAGE[backend]:-}" ]; then
        export BACKEND_IMAGE="${PUBLISHED_IMAGE[backend]}"
    else
        export BACKEND_IMAGE="${IMAGE_PREFIX}/backend:${VERSION}"
    fi

    if [ -n "${PUBLISHED_IMAGE[frontend]:-}" ]; then
        export FRONTEND_IMAGE="${PUBLISHED_IMAGE[frontend]}"
    else
        export FRONTEND_IMAGE="${IMAGE_PREFIX}/frontend:${VERSION}"
    fi
}

# Refuse a release whose manifests cannot be rendered, before it acquires a
# credential or changes anything. Every value a manifest carries is resolved
# here: the names below are checked directly so that all of the missing ones
# are reported at once, and then every selected group is rendered and
# discarded, which asks the renderer -- the authority for the required set --
# about the tokens this script does not name, including the ones it derives.
assert_manifest_tokens() {
    echo "Checking the manifest values..."

    local token
    local missing=""
    local -a required=("${REQUIRED_RENDER_TOKENS[@]}")

    if [ "${PROVISION_ADMIN_CREDENTIAL:-false}" = "true" ]; then
        required+=("${ADMIN_CREDENTIAL_RENDER_TOKENS[@]}")
    fi

    for token in "${required[@]}"; do
        if [ -z "${!token-}" ]; then
            missing="${missing} ${token}"
        fi
    done

    if [ -n "${missing}" ]; then
        echo "Required manifest value(s) not set:${missing}." >&2
        echo "The manifest renderer defaults none of them, and a release" \
            "that reached the cluster without them would fail after" \
            "acquiring credentials. Run ${BASH_SOURCE[0]} --help for every" \
            "input." >&2
        exit 1
    fi

    "${RENDER}" all > /dev/null

    if [ "${PROVISION_ADMIN_CREDENTIAL:-false}" = "true" ]; then
        "${RENDER}" admin-credential > /dev/null
    fi

    echo "Every manifest this release applies renders."
}

acquire_cluster_credentials() {
    echo "Acquiring credentials for ${GKE_CLUSTER} in ${GKE_REGION}..."

    local active_account
    local context

    if ! active_account="$(gcloud auth list --quiet \
        --filter=status:ACTIVE --format="value(account)")" \
        || [ -z "${active_account}" ]; then
        echo "No active Google Cloud credentials are available to this" \
            "environment." >&2
        exit 1
    fi
    echo "Using credentials for account $(account_reference "${active_account}")"

    # A kubeconfig private to this run. get-credentials writes exactly
    # one context into it and every kubectl call below reads it, so no
    # context that was already active anywhere on this host is reachable.
    KUBECONFIG_FILE="$(mktemp)"
    export KUBECONFIG="${KUBECONFIG_FILE}"

    # The cluster is regional and its control plane carries no external
    # IP address, so it is addressed by region and reached over its
    # DNS-based endpoint, which is authorized by IAM.
    gcloud container clusters get-credentials "${GKE_CLUSTER}" \
        --region="${GKE_REGION}" \
        --project="${GCP_PROJECT_ID}" \
        --dns-endpoint \
        --quiet

    context="$(kubectl config current-context)"

    if [ "${context}" != "${EXPECTED_CONTEXT}" ]; then
        echo "The context this run wrote is ${context} rather than" \
            "${EXPECTED_CONTEXT}." >&2
        exit 1
    fi

    if ! kubectl get namespace "${K8S_NAMESPACE}" \
        --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" > /dev/null; then
        echo "Namespace ${K8S_NAMESPACE} does not exist in" \
            "${context}." >&2
        exit 1
    fi

    echo "Targeting ${context}, namespace ${K8S_NAMESPACE}"
}

assert_release_inventory() {
    echo "Checking the release inventory..."

    local workload
    local containers

    for workload in "${RELEASE_WORKLOADS[@]}"; do
        if ! kubectl get "deployment/${workload}" \
            --namespace="${K8S_NAMESPACE}" \
            --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" > /dev/null; then
            echo "Deployment ${workload} does not exist in namespace" \
                "${K8S_NAMESPACE}." >&2
            echo "This script publishes into an inventory that already" \
                "exists and creates no workload." >&2
            exit 1
        fi

        containers="$(kubectl get "deployment/${workload}" \
            --namespace="${K8S_NAMESPACE}" \
            --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" \
            -o jsonpath='{.spec.template.spec.containers[*].name}')"

        if [[ " ${containers} " != *" ${workload} "* ]]; then
            echo "Deployment ${workload} declares the containers" \
                "[${containers}], none of which is named" \
                "${workload}." >&2
            exit 1
        fi
    done

    echo "Every Deployment and container this release addresses exists."
}

refuse_reused_tags() {
    echo "Checking that ${VERSION} names no published image..."

    local workload

    for workload in "${RELEASE_WORKLOADS[@]}"; do
        if gcloud artifacts docker images describe \
            "${IMAGE_PREFIX}/${workload}:${VERSION}" \
            --project="${GCP_PROJECT_ID}" --quiet > /dev/null 2>&1; then
            echo "${IMAGE_PREFIX}/${workload}:${VERSION} is already" \
                "published." >&2
            echo "Release under a tag that has not been used before, so" \
                "the rollout cannot resolve to earlier content." >&2
            exit 1
        fi
    done
}

publish_images() {
    echo "Building and publishing images..."

    local workload
    local dockerfile
    local context
    local reference
    local digest
    local name
    local -a names

    gcloud auth configure-docker "${REGISTRY_HOST}" --quiet

    for workload in "${RELEASE_WORKLOADS[@]}"; do
        dockerfile="${REPO_ROOT}/${WORKLOAD_DOCKERFILE[${workload}]}"
        context="${REPO_ROOT}/${WORKLOAD_CONTEXT[${workload}]}"

        if [ ! -f "${dockerfile}" ]; then
            echo "The image definition ${dockerfile} is missing." >&2
            exit 1
        fi

        if [ ! -d "${context}" ]; then
            echo "The build context ${context} is missing." >&2
            exit 1
        fi

        reference="${IMAGE_PREFIX}/${workload}:${VERSION}"

        # One --build-arg per name the image declares, carried in this
        # function's own positional parameters so each flag and value is a
        # separate word and a value holding whitespace reaches the build
        # whole. The backend declares none, so its list stays empty and
        # expands to nothing. read_build_arguments has already refused an
        # empty value for every name passed here.
        names=()
        read -r -a names <<< "${WORKLOAD_BUILD_ARGUMENTS[${workload}]}"
        set --
        if [ "${#names[@]}" -gt 0 ]; then
            for name in "${names[@]}"; do
                set -- "$@" --build-arg "${name}=${!name}"
            done
        fi

        timeout "${COMMAND_TIMEOUT_SECONDS}" docker build \
            --file "${dockerfile}" "$@" --tag "${reference}" "${context}"
        timeout "${COMMAND_TIMEOUT_SECONDS}" docker push "${reference}"

        # The registry is asked for the digest it stored, so the rollout
        # below names content rather than a tag that can be moved.
        digest="$(gcloud artifacts docker images describe "${reference}" \
            --project="${GCP_PROJECT_ID}" --quiet \
            --format="value(image_summary.digest)")"

        if ! [[ ${digest} =~ ${DIGEST_PATTERN} ]]; then
            echo "The registry reported no digest for ${reference}." >&2
            exit 1
        fi

        PUBLISHED_IMAGE["${workload}"]="${IMAGE_PREFIX}/${workload}@${digest}"
        echo "Published ${PUBLISHED_IMAGE[${workload}]}"
    done
}

# Applies the Alembic revisions as the one-shot Job
# infrastructure/kubernetes/60-migration-job.yaml declares, which is the
# same manifest .github/workflows/cd.yml applies, so both delivery paths
# migrate through one specification.
#
# The specification is owned by this repository rather than copied from a
# Deployment found in the cluster, so a first release -- where no Deployment
# exists yet to copy from -- migrates exactly as a later one does. It also
# means the migration runs under its own least-privilege identity and reads
# only DATABASE_URL, rather than inheriting every credential the serving
# pod mounts.
apply_database_migrations() {
    echo "Applying database migrations..."

    local job_name

    # Refreshed so the rendered Job carries the digest this run published
    # rather than the tag it was pushed under.
    export_render_tokens

    # One name per release, read from the renderer that renders the Job, so
    # the object applied is the object waited on. The renderer folds the tag
    # to the alphabet and length a Kubernetes object name accepts, which a
    # name assembled here would not.
    job_name="$("${RENDER}" job-name migration)"

    "${RENDER}" migration | kubectl apply --namespace="${K8S_NAMESPACE}" --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" -f -

    if ! kubectl --namespace="${K8S_NAMESPACE}" wait "job/${job_name}" \
        --for=condition=complete --timeout="${MIGRATION_TIMEOUT}"; then
        echo "alembic upgrade head did not complete." >&2
        if ! kubectl --namespace="${K8S_NAMESPACE}" logs "job/${job_name}" --tail=200 --request-timeout="${KUBECTL_REQUEST_TIMEOUT}"; then
            echo "logs for ${job_name} were not retrievable" >&2
        fi
        if ! kubectl --namespace="${K8S_NAMESPACE}" describe "job/${job_name}" --request-timeout="${KUBECTL_REQUEST_TIMEOUT}"; then
            echo "${job_name} was not describable" >&2
        fi
        exit 1
    fi

    kubectl --namespace="${K8S_NAMESPACE}" logs "job/${job_name}" --tail=200 --request-timeout="${KUBECTL_REQUEST_TIMEOUT}"

    echo "The schema is at the head revision."
}

# Wait for the manifest-driven rollout; this function does not mutate
# images.
await_rollout() {
    echo "Waiting for the rollout to land..."

    local workload

    for workload in "${RELEASE_WORKLOADS[@]}"; do
        kubectl rollout status "deployment/${workload}" \
            --namespace="${K8S_NAMESPACE}" \
            --timeout="${ROLLOUT_TIMEOUT}"
    done
}

verify_running_images() {
    echo "Verifying what is running..."

    local workload
    local digest
    local selector
    local observed
    local running
    local -a running_images

    for workload in "${RELEASE_WORKLOADS[@]}"; do
        digest="${PUBLISHED_IMAGE[${workload}]##*@}"

        selector="$(kubectl get "deployment/${workload}" \
            --namespace="${K8S_NAMESPACE}" \
            --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" -o json \
            | jq -r '.spec.selector.matchLabels | to_entries
                     | map("\(.key)=\(.value)") | join(",")')"

        if [ -z "${selector}" ]; then
            echo "Deployment ${workload} declares no pod selector." >&2
            exit 1
        fi

        # The digest each container reports it is running, rather than
        # the tag the Deployment was asked for.
        observed="$(kubectl get pods --namespace="${K8S_NAMESPACE}" \
            --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" \
            --selector="${selector}" -o json \
            | jq -r --arg container "${workload}" \
                '.items[]
                 | select(.metadata.deletionTimestamp == null)
                 | .status.containerStatuses // []
                 | .[]
                 | select(.name == $container)
                 | .imageID')"

        if [ -z "${observed}" ]; then
            echo "No running ${workload} container was observed in" \
                "namespace ${K8S_NAMESPACE}." >&2
            exit 1
        fi

        mapfile -t running_images <<< "${observed}"

        for running in "${running_images[@]}"; do
            if [[ ${running} != *"${digest}"* ]]; then
                echo "A ${workload} container reports ${running}, which" \
                    "does not carry ${digest}." >&2
                exit 1
            fi
        done

        echo "${workload} is running ${digest}"
    done
}

deploy_cloud_function() {
    local status

    if [ "${CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED}" != "true" ]; then
        echo "The Cloud Function step was not performed." >&2
        echo "${CLOUD_FUNCTION_NAME} is pinned to the" \
            "${CLOUD_FUNCTION_RUNTIME} runtime, which Google's Cloud Run" \
            "functions support schedule lists as decommissioned: a" \
            "decommissioned runtime is refused for both create and" \
            "update. The pin is frozen, so this step stays blocked until" \
            "a release owner authorizes it by setting" \
            "CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED=true." >&2
        echo "The conflict and the decision it awaits are recorded in" \
            "docs/security/RESIDUAL_RISK.md." >&2
        return 0
    fi

    echo "Deploying ${CLOUD_FUNCTION_NAME}..."

    # Validate the Cloud Function source URI and object before
    # deployment.
    case "${FUNCTION_SOURCE}" in
        gs://*/*) ;;
        *)
            echo "The function source ${FUNCTION_SOURCE} is not a" \
                "gs://<bucket>/<object> address." >&2
            exit 1
            ;;
    esac

    # And it has to be the archive Terraform published rather than merely
    # an object answering to that name. Reading it first also fails while
    # nothing has changed: deploying from an absent archive fails after
    # the function has been created, leaving a function with no source.
    local published
    if ! published="$(timeout "${COMMAND_TIMEOUT_SECONDS}" \
        gcloud storage objects describe "${FUNCTION_SOURCE}" \
        --project="${GCP_PROJECT_ID}" \
        --quiet \
        --format="value(md5_hash)")"; then
        echo "The function source ${FUNCTION_SOURCE} does not exist," \
            "or this account cannot read it." >&2
        echo "Terraform provisions it; apply the configuration in" \
            "infrastructure/terraform first." >&2
        exit 1
    fi

    # The digest is compared, not just the name, so an object replaced in
    # the bucket after the apply is refused instead of deployed. Both
    # values are the same base64 MD5, so neither is re-encoded here.
    published="${published//[[:space:]]/}"
    if [ "${published}" != "${CLOUD_FUNCTION_SOURCE_MD5}" ]; then
        echo "The function source ${FUNCTION_SOURCE} carries digest" \
            "\"${published}\" and CLOUD_FUNCTION_SOURCE_MD5 names" \
            "\"${CLOUD_FUNCTION_SOURCE_MD5}\"." >&2
        echo "That object is not the archive Terraform published. Re-read" \
            "the cloud_function_source_object and" \
            "cloud_function_source_md5 outputs, and do not deploy it." >&2
        exit 1
    fi

    if ! timeout "${COMMAND_TIMEOUT_SECONDS}" \
        gcloud functions deploy "${CLOUD_FUNCTION_NAME}" \
        --project="${GCP_PROJECT_ID}" \
        --region="${GKE_REGION}" \
        --source="${FUNCTION_SOURCE}" \
        --entry-point="${CLOUD_FUNCTION_ENTRY_POINT}" \
        --runtime python39 \
        --trigger-http \
        --no-allow-unauthenticated \
        --quiet; then
        echo "Deploying ${CLOUD_FUNCTION_NAME} on the" \
            "${CLOUD_FUNCTION_RUNTIME} runtime failed." >&2
        exit 1
    fi

    # The same name, project and region the deploy above named, so the
    # status reported is the status of the resource just deployed.
    status="$(timeout "${COMMAND_TIMEOUT_SECONDS}" \
        gcloud functions describe "${CLOUD_FUNCTION_NAME}" \
        --project="${GCP_PROJECT_ID}" \
        --region="${GKE_REGION}" \
        --quiet \
        --format="value(status)")"

    if [ "${status}" != "ACTIVE" ]; then
        echo "Cloud Function ${CLOUD_FUNCTION_NAME} reports status" \
            "${status:-unknown} rather than ACTIVE." >&2
        exit 1
    fi

    echo "Cloud Function ${CLOUD_FUNCTION_NAME} is ${status}"

    # The effective invoker policy is read back from the deployed function.
    # It reports every binding, including one added outside this script.
    local effective_members
    local public_principal

    # Revoke public invokers explicitly and verify the effective policy
    # after deployment.
    for public_principal in "allUsers" "allAuthenticatedUsers"; do
        timeout "${COMMAND_TIMEOUT_SECONDS}" \
            gcloud functions remove-iam-policy-binding \
            "${CLOUD_FUNCTION_NAME}" \
            --project="${GCP_PROJECT_ID}" \
            --region="${GKE_REGION}" \
            --member="${public_principal}" \
            --role="roles/cloudfunctions.invoker" \
            --quiet >/dev/null 2>&1 || true
    done

    effective_members="$(timeout "${COMMAND_TIMEOUT_SECONDS}" \
        gcloud functions get-iam-policy "${CLOUD_FUNCTION_NAME}" \
        --project="${GCP_PROJECT_ID}" \
        --region="${GKE_REGION}" \
        --quiet \
        --flatten="bindings[].members" \
        --filter="bindings.role=roles/cloudfunctions.invoker" \
        --format="value(bindings.members)")"

    for public_principal in "allUsers" "allAuthenticatedUsers"; do
        if printf '%s' "${effective_members}" \
            | grep -Fq "${public_principal}"; then
            echo "Cloud Function ${CLOUD_FUNCTION_NAME} still grants" \
                "${public_principal}; remove that binding before this" \
                "deployment is accepted." >&2
            exit 1
        fi
    done

    echo "Cloud Function ${CLOUD_FUNCTION_NAME} grants no public principal"
}

apply_prerequisites() {
    echo "Applying the workload prerequisites..."

    # The namespace, the service accounts, the settings map and the Secret
    # Manager provider class. None carries a serving image, so nothing
    # starts here. Every credential is fetched by the provider class at pod
    # start; this script reads none.
    "${RENDER}" prerequisites | kubectl apply --namespace="${K8S_NAMESPACE}" --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" -f -
}

# Gives the seeded administrator a credential, replacing the value
# 0002_seed_single_admin.py stores, which no password produces. Skipped
# unless PROVISION_ADMIN_CREDENTIAL is set to true. It runs after
# run_migration, which is what creates the account it addresses.
#
# The step is safe to repeat. The module leaves a credential already in
# place alone unless ADMIN_CREDENTIAL_RESET is true, and re-asserts that
# exactly one account holds the administrative role before committing.
# docs/security/CREDENTIAL_ROTATION.md records when to run it.
provision_admin_credential() {
    local job_name

    if [ "${PROVISION_ADMIN_CREDENTIAL:-false}" != "true" ]; then
        echo "Skipping administrator credential provisioning; set" \
            "PROVISION_ADMIN_CREDENTIAL=true to run it."
        return 0
    fi

    echo "Provisioning the administrator credential..."
    export ADMIN_CREDENTIAL_RESET="${ADMIN_CREDENTIAL_RESET:-false}"

    # The name the rendered Job carries, read from the renderer that renders
    # it, so the object applied is the object waited on.
    job_name="$("${RENDER}" job-name admin-credential)"

    # A completed Job is retained by ttlSecondsAfterFinished and a Job's pod
    # template cannot be changed in place, so a reset on a release that has
    # already provisioned would be refused. Any previous run of this name is
    # removed first and its removal confirmed, so the apply below creates
    # the object it then waits on.
    if kubectl --namespace="${K8S_NAMESPACE}" get "job/${job_name}" \
        --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" >/dev/null 2>&1; then
        kubectl --namespace="${K8S_NAMESPACE}" delete "job/${job_name}" \
            --wait=true --timeout="${MIGRATION_TIMEOUT}" \
            --request-timeout="${KUBECTL_REQUEST_TIMEOUT}"
    fi
    if kubectl --namespace="${K8S_NAMESPACE}" get "job/${job_name}" \
        --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" >/dev/null 2>&1; then
        echo "${job_name} still exists after deletion; it was not" \
            "recreated." >&2
        exit 1
    fi

    "${RENDER}" admin-credential | kubectl apply --namespace="${K8S_NAMESPACE}" --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" -f -

    if ! kubectl --namespace="${K8S_NAMESPACE}" wait "job/${job_name}" \
        --for=condition=complete --timeout="${MIGRATION_TIMEOUT}"; then
        echo "administrator credential provisioning did not complete." >&2
        if ! kubectl --namespace="${K8S_NAMESPACE}" logs "job/${job_name}" --tail=200 --request-timeout="${KUBECTL_REQUEST_TIMEOUT}"; then
            echo "logs for ${job_name} were not retrievable" >&2
        fi
        if ! kubectl --namespace="${K8S_NAMESPACE}" describe "job/${job_name}" --request-timeout="${KUBECTL_REQUEST_TIMEOUT}"; then
            echo "${job_name} was not describable" >&2
        fi
        exit 1
    fi

    kubectl --namespace="${K8S_NAMESPACE}" logs "job/${job_name}" --tail=200 --request-timeout="${KUBECTL_REQUEST_TIMEOUT}"
}

# Copies the shared rate-limit store's address out of Secret Manager into
# the Kubernetes secret every workload references. The value carries the
# store's AUTH string, so it is read into a file rather than onto a command
# line, it reaches no manifest and no log, and an address naming a store held
# inside one process is refused here rather than by each pod's own startup
# validation.
#
# Runs after apply_prerequisites, because the namespace the secret is created
# in is one of them.
publish_rate_limit_store_address() {
    echo "Publishing the shared rate-limit store address..."

    local work
    local address

    umask 077
    work="$(mktemp -d)"
    address="${work}/${RATE_LIMIT_SETTING}"

    timeout "${COMMAND_TIMEOUT_SECONDS}" \
        gcloud secrets versions access latest \
        --secret="${RATE_LIMIT_SETTING}" \
        --project="${GCP_PROJECT_ID}" \
        --quiet > "${address}"

    if [ ! -s "${address}" ]; then
        rm -rf "${work}"
        echo "Secret Manager secret ${RATE_LIMIT_SETTING} carries no" \
            "value." >&2
        exit 1
    fi

    if grep -Eq '^(bounded-memory|memory|async\+memory)://' "${address}"; then
        rm -rf "${work}"
        echo "${RATE_LIMIT_SETTING} names a store held inside one process;" \
            "it must name storage shared by every process." >&2
        exit 1
    fi

    kubectl create secret generic "${RATE_LIMIT_STORE_SECRET}" \
        --namespace="${K8S_NAMESPACE}" \
        --from-file="${RATE_LIMIT_SETTING}=${address}" \
        --dry-run=client -o yaml \
        | kubectl apply --namespace="${K8S_NAMESPACE}" --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" -f -

    rm -rf "${work}"
}

deploy_workloads() {
    echo "Applying the serving workloads..."

    # Refreshed so the rendered manifests carry the digests this run
    # published rather than the tag they were pushed under.
    export_render_tokens

    # Reached only after the migration above has completed, so the new code
    # never reads a schema the migration has not applied. The manifests
    # carry this release's images, so applying them is the rollout.
    "${RENDER}" workloads | kubectl apply --namespace="${K8S_NAMESPACE}" --request-timeout="${KUBECTL_REQUEST_TIMEOUT}" -f -
}

probe_endpoint() {
    local url="$1"
    local what="$2"
    local attempt

    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if curl --fail --silent --show-error \
            --connect-timeout "${CURL_CONNECT_TIMEOUT}" \
            --max-time "${CURL_MAX_TIME}" "${url}"; then
            return 0
        fi
        echo "${what} probe attempt ${attempt} did not answer, retrying"
        sleep 5
    done

    echo "the backend ${what} endpoint did not answer on ${url}" >&2
    exit 1
}

probe_health() {
    kubectl --namespace="${K8S_NAMESPACE}" port-forward deployment/backend \
        "${HEALTH_PORT}:8000" &

    # Recorded at script scope so the single EXIT trap installed above
    # closes the forward, and closes it whether the probes below succeed,
    # fail or are interrupted.
    HEALTH_FORWARD_PID=$!

    sleep 5

    # Liveness answers from the process alone; readiness answers only once
    # every dependency the request path needs is reachable. Both are
    # probed, because a rollout that answers the first and not the second
    # is serving no request and must not be reported as healthy.
    probe_endpoint "http://127.0.0.1:${HEALTH_PORT}/health" "liveness"
    probe_endpoint "http://127.0.0.1:${HEALTH_PORT}/health/ready" "readiness"
}

main() {
    parse_arguments "$@"
    check_tools
    read_inputs
    build_references
    assert_manifest_tokens
    acquire_cluster_credentials
    apply_prerequisites
    publish_rate_limit_store_address
    assert_release_inventory
    refuse_reused_tags
    publish_images
    apply_database_migrations
    provision_admin_credential
    deploy_workloads
    await_rollout
    verify_running_images
    probe_health
    deploy_cloud_function

    echo "Release ${VERSION} completed: ${RELEASE_WORKLOADS[*]} are" \
        "running the digests published by this run."
}

main "$@"
