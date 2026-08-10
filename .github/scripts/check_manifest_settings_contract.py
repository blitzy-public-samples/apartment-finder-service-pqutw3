"""Checks the deployment manifests against the settings contract.

Run by the ``infrastructure`` job of ``.github/workflows/ci.yml`` and
runnable from a workstation with ``python
.github/scripts/check_manifest_settings_contract.py``.

The check is a script rather than a block embedded in the workflow so that
it is covered by the repository's own lint, so it can be run without a
workflow runner, and because a block of this size is piped to ShellCheck by
actionlint and does not complete there.

What is asserted, against ``infrastructure/kubernetes``:

* the ``backend-config`` ConfigMap declares every setting the model
  declares that is neither one of the credentials the Secret Manager CSI
  driver mounts nor one the deployment publishes as a Kubernetes secret
* the ConfigMap selects the managed secret backend
* the ``backend-secrets`` provider class mounts exactly the managed
  credentials and syncs none of them into a Kubernetes secret
* no manifest declares a ``Secret`` carrying a literal value
* every container that reads the ConfigMap also references the secret the
  deployment publishes, and declares no optional configuration source
* no container passes an inline environment value other than the ones
  recorded in :data:`PERMITTED_INLINE_ENVIRONMENT`

The manifests carry substitution tokens the release renders. Their values
are not knowable here and no assertion reads one, so each is replaced with
a stand-in before parsing.
"""

import pathlib
import re
import sys

import yaml

# The repository root, so the check runs the same way from a workflow step
# and from a workstation regardless of which directory python was started in.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from backend.app.core.config import (  # noqa: E402
    MANAGED_BACKEND_NAME,
    MANAGED_SECRET_SETTINGS,
    PIPELINE_SECRET_SETTINGS,
    Settings,
)

#: Directory holding the one manifest inventory both delivery paths apply.
MANIFEST_DIR = pathlib.Path("infrastructure/kubernetes")

#: Secret the deployment publishes from Secret Manager, and which every
#: workload that constructs ``Settings`` references.
PUBLISHED_SECRET = "backend-rate-limit-store"

#: Provider class that mounts the managed credentials.
PROVIDER_CLASS = "backend-secrets"

#: ConfigMap carrying the non-credential settings.
CONFIG_MAP = "backend-config"

#: One substitution token.
TOKEN = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")

#: Inline environment names a container may declare, and why.
#:
#: ``ENV_FILE`` is set empty so the application reads no environment file in
#: the cluster: every value arrives from the ConfigMap, the published secret
#: or the mounted credential files. ``ADMIN_CREDENTIAL_RESET`` selects
#: whether the operator step replaces a credential that is already in place.
#: Neither carries a secret.
PERMITTED_INLINE_ENVIRONMENT = frozenset(
    {"ENV_FILE", "ADMIN_CREDENTIAL_RESET"}
)


def _parsed(path):
    """Returns every object one manifest declares, tokens resolved."""
    body = TOKEN.sub("rendered-at-release", path.read_text(encoding="utf-8"))
    return [document for document in yaml.safe_load_all(body) if document]


def _pod_templates(document):
    """Returns the pod templates one object governs."""
    kind = document["kind"]
    if kind in ("Deployment", "Job"):
        return [document["spec"]["template"]]
    if kind == "CronJob":
        return [document["spec"]["jobTemplate"]["spec"]["template"]]
    return []


def _only(documents, kind, name):
    """Returns the single object of one kind and name."""
    matched = [
        document
        for document in documents
        if document["kind"] == kind and document["metadata"]["name"] == name
    ]
    assert len(matched) == 1, "%s/%s is declared %d times" % (
        kind,
        name,
        len(matched),
    )
    return matched[0]


def main():
    manifests = sorted(MANIFEST_DIR.glob("*.yaml"))
    assert manifests, "no deployment manifest was found in %s" % MANIFEST_DIR

    documents = {}
    for path in manifests:
        documents[path.name] = _parsed(path)
    every_document = [
        document for group in documents.values() for document in group
    ]

    credentials = set(MANAGED_SECRET_SETTINGS)
    published = set(PIPELINE_SECRET_SETTINGS)
    declared = set(Settings.__fields__)

    config_map = _only(every_document, "ConfigMap", CONFIG_MAP)
    assert set(config_map["data"]) == declared - credentials - published, (
        "the ConfigMap must carry every setting that is neither a credential "
        "nor published as a secret by the deployment; missing %s, extra %s"
        % (
            sorted(
                declared
                - credentials
                - published
                - set(config_map["data"])
            ),
            sorted(set(config_map["data"]) - declared),
        )
    )
    assert config_map["data"]["SECRET_BACKEND"] == MANAGED_BACKEND_NAME, (
        "the ConfigMap must select the managed secret backend"
    )

    # The provider class fetches the credentials from Secret Manager at pod
    # start. It declares no secretObjects on purpose: a synced Kubernetes
    # secret would place every one of them in etcd, which is what mounting
    # them avoids.
    provider = _only(every_document, "SecretProviderClass", PROVIDER_CLASS)
    mounted = yaml.safe_load(provider["spec"]["parameters"]["secrets"])
    assert {entry["path"] for entry in mounted} == credentials, (
        "the mounted secrets must be exactly the managed settings"
    )
    assert "secretObjects" not in provider["spec"], (
        "the provider class must not sync the credentials into etcd"
    )

    for name, group in sorted(documents.items()):
        for document in group:
            assert document["kind"] != "Secret", (
                "%s declares a Secret with a literal value" % name
            )
            for template in _pod_templates(document):
                for container in template["spec"]["containers"]:
                    _check_container(name, container)

    print("%d manifests match the settings contract" % len(manifests))


def _check_container(name, container):
    """Asserts one container reads its settings as the contract requires."""
    for entry in container.get("env") or []:
        assert entry["name"] in PERMITTED_INLINE_ENVIRONMENT, (
            "%s: %s passes the inline environment value %s; only references "
            "and the recorded exceptions are permitted"
            % (name, container["name"], entry["name"])
        )
        assert "valueFrom" not in entry, (
            "%s: %s reads %s indirectly; declare it in the ConfigMap instead"
            % (name, container["name"], entry["name"])
        )

    sources = container.get("envFrom") or []
    if not any("configMapRef" in entry for entry in sources):
        return

    referenced = {
        entry["secretRef"]["name"] for entry in sources if "secretRef" in entry
    }
    assert PUBLISHED_SECRET in referenced, (
        "%s: %s reads %s without %s, so it would start on the in-process "
        "rate-limit default the application refuses"
        % (name, container["name"], CONFIG_MAP, PUBLISHED_SECRET)
    )
    for entry in sources:
        for kind in entry:
            assert entry[kind].get("optional") is False, (
                "%s: %s declares an optional %s"
                % (name, container["name"], kind)
            )


if __name__ == "__main__":
    main()
    sys.exit(0)
