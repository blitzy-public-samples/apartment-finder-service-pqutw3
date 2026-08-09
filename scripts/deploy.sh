#!/bin/bash
set -euo pipefail

# Check the environment variables this script requires
for required_var in GCP_PROJECT_ID VERSION; do
  if [ -z "${!required_var:-}" ]; then
    echo "Required environment variable ${required_var} is not set." >&2
    exit 1
  fi
done

# Authenticate with Google Cloud
echo "Authenticating with Google Cloud..."
if ! active_account="$(gcloud auth list --filter=status:ACTIVE --format="value(account)")" || [ -z "${active_account}" ]; then
  echo "No active Google Cloud credentials are available to this environment." >&2
  exit 1
fi
echo "Using credentials for ${active_account}"
gcloud config set project ${GCP_PROJECT_ID}

# Build and push Docker images
echo "Building and pushing Docker images..."
docker build -t gcr.io/${GCP_PROJECT_ID}/app:${VERSION} .
docker push gcr.io/${GCP_PROJECT_ID}/app:${VERSION}

# Update Kubernetes deployments
echo "Updating Kubernetes deployments..."
kubectl set image deployment/app-deployment app=gcr.io/${GCP_PROJECT_ID}/app:${VERSION}
kubectl rollout status deployment/app-deployment

# Apply database migrations
echo "Applying database migrations..."
migration_pod="$(kubectl get pods -l app=app-deployment -o jsonpath="{.items[0].metadata.name}")"
if [ -z "${migration_pod}" ]; then
  echo "No pod matched app=app-deployment; database migrations were not applied." >&2
  exit 1
fi
kubectl exec "${migration_pod}" -- python -m alembic -c backend/alembic.ini upgrade head

# Update Cloud Functions
echo "Updating Cloud Functions..."
gcloud functions deploy function-name --source=./functions --runtime python39 --trigger-http

# Verify deployment status
echo "Verifying deployment status..."
ready_replicas="$(kubectl get deployment/app-deployment -o jsonpath="{.status.readyReplicas}")"
desired_replicas="$(kubectl get deployment/app-deployment -o jsonpath="{.spec.replicas}")"
if [ "${ready_replicas:-0}" != "${desired_replicas}" ]; then
  echo "Deployment app-deployment has ${ready_replicas:-0} of ${desired_replicas:-unknown} replicas ready." >&2
  exit 1
fi
echo "Deployment app-deployment has ${ready_replicas:-0} of ${desired_replicas} replicas ready"
function_status="$(gcloud functions describe function-name --format="value(status)")"
if [ "${function_status}" != "ACTIVE" ]; then
  echo "Cloud Function function-name reports status ${function_status:-unknown} instead of ACTIVE." >&2
  exit 1
fi
echo "Cloud Function function-name is ${function_status}"

echo "Deployment completed successfully!"
