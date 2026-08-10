#!/bin/bash
#
# Releases apartment-finder-service to Google Kubernetes Engine, and to
# Cloud Functions once a release owner has authorized that step.
#
# The release inventory is fixed, and it is the same inventory
# .github/workflows/cd.yml addresses: the Deployments named in
# RELEASE_WORKLOADS below, each running one container of the same name,
# in the namespace K8S_NAMESPACE names. This script creates neither
# Deployment. It asserts that each one exists, carrying the container
# name it addresses, before it changes anything.
#
# The schema is migrated from the newly built image before any workload
# serves that image, and the release aborts unless the migration
# succeeds, so no container starts against a schema it does not match.
#
# Every step is checked and the script stops at the first failure, so the
# closing success message is printed only once all of them have
# succeeded. The images, contexts and workload names below are the ones
# infrastructure/docker/docker-compose.yml and
# .github/workflows/cd.yml name, so both deployment paths act on the same
# artefacts.
#
# Run `scripts/deploy.sh --help` for every input and its accepted form.
#
# Design rationale is recorded in docs/security/DECISION_LOG.md.

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

# Workload whose image carries the Alembic revisions. The container the
# revisions run under and the configuration file they are applied with are
# declared by infrastructure/kubernetes/60-migration-job.yaml, which this
# script renders rather than restating: a second copy of either here could
# disagree with the manifest the release actually applies.
readonly MIGRATION_WORKLOAD="backend"

# Cloud Function contract. Every value here matches
# infrastructure/terraform/main.tf, which owns the function and its
# invoker binding. CLOUD_FUNCTION_RUNTIME is pinned and is not advanced
# here; see deploy_cloud_function below.
readonly CLOUD_FUNCTION_NAME="apartment-finder-probe"
readonly CLOUD_FUNCTION_ENTRY_POINT="hello_world"
readonly CLOUD_FUNCTION_RUNTIME="python39"
readonly CLOUD_FUNCTION_SOURCE_OBJECT="function-source.zip"
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
# them. Each is re-exported so a value set in the caller's shell without
# `export` still reaches the renderer. The renderer owns the required-token
# list and names any that is absent, so this script does not restate it.
readonly OPERATOR_RENDER_TOKENS=(
    "BACKEND_ENVIRONMENT"
    "BACKEND_ALLOWED_ORIGINS"
    "BACKEND_ALLOWED_HOSTS"
    "PAYPAL_CLIENT_ID"
    "PAYPAL_MODE"
    "PAYPAL_API_BASE"
    "PAYPAL_RETURN_URL"
    "PAYPAL_CANCEL_URL"
    "ZILLOW_API_URL"
    "FROM_EMAIL"
    "BACKEND_SERVICE_ACCOUNT"
    "FRONTEND_SERVICE_ACCOUNT"
    "MIGRATION_SERVICE_ACCOUNT"
    "MIGRATION_SERVICE_ACCOUNT_ID"
    "ADMIN_PROVISIONER_SERVICE_ACCOUNT"
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

# Inputs, each read from the environment and validated by read_inputs.
GCP_PROJECT_ID="${GCP_PROJECT_ID:-}"
GKE_CLUSTER="${GKE_CLUSTER:-}"
GKE_REGION="${GKE_REGION:-}"
K8S_NAMESPACE="${K8S_NAMESPACE:-}"
VERSION="${VERSION:-}"
ARTIFACT_REGISTRY_REPOSITORY="${ARTIFACT_REGISTRY_REPOSITORY:-apartment-finder}"
CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED="${CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED:-false}"

# References built from the inputs by build_references.
REGISTRY_HOST=""
IMAGE_PREFIX=""
EXPECTED_CONTEXT=""
FUNCTION_SOURCE=""

# Kubeconfig this run writes its one context into, removed by cleanup.
KUBECONFIG_FILE=""

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

Optional:
  ARTIFACT_REGISTRY_REPOSITORY   Artifact Registry Docker repository the
                                 images are published to.
                                 Default: apartment-finder
  CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED
                                 "true" runs the Cloud Function step.
                                 Default: false, which reports the step
                                 as blocked and performs it not at all.

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

# Reached only through the EXIT trap below, and only ever after
# acquire_cluster_credentials has set KUBECONFIG_FILE, which is why the
# reachability note is suppressed here rather than the guard being dropped.
#
# The migration runs as a Job this script renders, and the Job carries its own
# deadline and retention, so there is no pod for this handler to remove. Only
# the kubeconfig this run wrote is its to clean up.
cleanup() {
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
}

build_references() {
    REGISTRY_HOST="${GKE_REGION}-docker.pkg.dev"
    readonly REGISTRY_HOST

    IMAGE_PREFIX="${REGISTRY_HOST}/${GCP_PROJECT_ID}"
    IMAGE_PREFIX="${IMAGE_PREFIX}/${ARTIFACT_REGISTRY_REPOSITORY}"
    readonly IMAGE_PREFIX

    EXPECTED_CONTEXT="gke_${GCP_PROJECT_ID}_${GKE_REGION}_${GKE_CLUSTER}"
    readonly EXPECTED_CONTEXT

    FUNCTION_SOURCE="gs://${GCP_PROJECT_ID}"
    FUNCTION_SOURCE="${FUNCTION_SOURCE}${CLOUD_FUNCTION_SOURCE_BUCKET_SUFFIX}"
    FUNCTION_SOURCE="${FUNCTION_SOURCE}/${CLOUD_FUNCTION_SOURCE_OBJECT}"
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

        timeout "${COMMAND_TIMEOUT_SECONDS}" docker build \
            --file "${dockerfile}" --tag "${reference}" "${context}"
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

    # One name per release, matching metadata.name of
    # infrastructure/kubernetes/60-migration-job.yaml, which renders
    # backend-migrate-${IMAGE_TAG} and which export_render_tokens sets
    # IMAGE_TAG to VERSION for.
    local job_name="${MIGRATION_WORKLOAD}-migrate-${VERSION}"

    # Refreshed so the rendered Job carries the digest this run published
    # rather than the tag it was pushed under.
    export_render_tokens

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

# Waits for the rollout deploy_workloads started. It issues no image
# mutation of its own: an in-place image edit changes one field of whatever
# the cluster happens to hold and leaves every other property as it was
# found, so a workload whose probes, resources or security context were
# never applied would keep not having them. The rendered manifests carry
# this release's digests, so applying them is the rollout and this only
# waits for it to land.
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

    # The source is an address rather than a path, and gcloud reports a
    # malformed one only after it has begun the deployment. The form is
    # checked here so that a value that cannot name an object is refused
    # before anything is created.
    case "${FUNCTION_SOURCE}" in
        gs://*/*) ;;
        *)
            echo "The function source ${FUNCTION_SOURCE} is not a" \
                "gs://<bucket>/<object> address." >&2
            exit 1
            ;;
    esac

    # And the object it names has to exist. Deploying from an absent
    # archive fails after the function has been created, leaving a
    # function with no source behind; asking first fails while nothing
    # has changed.
    if ! timeout "${COMMAND_TIMEOUT_SECONDS}" \
        gcloud storage objects describe "${FUNCTION_SOURCE}" \
        --project="${GCP_PROJECT_ID}" \
        --quiet \
        --format="value(name)" > /dev/null; then
        echo "The function source ${FUNCTION_SOURCE} does not exist," \
            "or this account cannot read it." >&2
        echo "Terraform provisions it; apply the configuration in" \
            "infrastructure/terraform first." >&2
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

    # The effective invoker policy is read back rather than inferred from
    # the flags above, because a binding added outside this script would not
    # show up in them.
    local effective_members
    local public_principal

    # Omission is not revocation. Deploying a function does not change an
    # existing function's authentication status, so a public grant made by
    # an earlier deployment outlives --no-allow-unauthenticated above. Each
    # public principal is therefore removed explicitly, tolerating the
    # "binding not found" case, before the effective policy is read back.
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
    local job_name="backend-admin-credential-${VERSION}"

    if [ "${PROVISION_ADMIN_CREDENTIAL:-false}" != "true" ]; then
        echo "Skipping administrator credential provisioning; set" \
            "PROVISION_ADMIN_CREDENTIAL=true to run it."
        return 0
    fi

    echo "Provisioning the administrator credential..."
    export ADMIN_CREDENTIAL_RESET="${ADMIN_CREDENTIAL_RESET:-false}"
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
    local forward_pid

    kubectl --namespace="${K8S_NAMESPACE}" port-forward deployment/backend \
        "${HEALTH_PORT}:8000" &
    forward_pid=$!
    cleanup() {
        if kill "${forward_pid}" 2>/dev/null; then
            echo "closed the port forward"
        fi
    }
    trap cleanup EXIT

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
