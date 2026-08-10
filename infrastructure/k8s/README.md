# `infrastructure/k8s/` — consolidated into `infrastructure/kubernetes/`

This directory once held a second inventory of the same cluster. It no longer holds
any manifest, and nothing applies it.

## Why it was consolidated

Three inventories of the same objects existed at once, and two of them lived in this
directory under different naming conventions. The result was four objects declared
twice inside one directory — the `backend` and `frontend` Deployments and their
Services — with different specifications each time. Applying the directory with a
glob would have created each of them twice, and which specification survived would
have depended on the order the files were read. That is not a difference of style;
it is a cluster whose contents cannot be predicted from the repository.

## Where the manifests are now

[`infrastructure/kubernetes/`](../kubernetes/) is the single inventory. It is
substitution-templated and applied through
[`scripts/render_kubernetes_manifests.sh`](../../scripts/render_kubernetes_manifests.sh),
which both `.github/workflows/cd.yml` and `scripts/deploy.sh` invoke, so the
manifests that are validated are the manifests that are applied.

| Object | Manifest | Render group |
|---|---|---|
| Namespace | `00-namespace.yaml` | `prerequisites` |
| Service accounts, including the migration identity | `10-service-accounts.yaml` | `prerequisites` |
| Settings map | `20-backend-config.yaml` | `prerequisites` |
| Secret delivery, six credentials | `30-backend-secrets.yaml` | `prerequisites` |
| Secret delivery, the one the migration reads | `35-migration-secrets.yaml` | `prerequisites` |
| Backend Deployment and Service | `40-backend.yaml` | `workloads` |
| Backend autoscaler | `45-backend-hpa.yaml` | `workloads` |
| Frontend Deployment and Service | `50-frontend.yaml` | `workloads` |
| Frontend autoscaler | `55-frontend-hpa.yaml` | `workloads` |
| Listing ingestion schedule | `65-ingestion-cronjob.yaml` | `workloads` |
| Schema migration | `60-migration-job.yaml` | `migration` |
| Administrator credential provisioning | `70-admin-credential-job.yaml` | `admin-credential` |

## What was carried across and what was dropped

The autoscalers and the ingestion schedule were unique to this directory and were
carried across, converted to the surviving substitution style. The ingestion pod was
additionally changed to read its credentials from the mounted files rather than from
a synchronised Kubernetes Secret, so that it matches the other workloads and no
credential is written into the cluster datastore.

Everything else here duplicated an object `infrastructure/kubernetes/` already
declared, and was dropped rather than reconciled twice.
