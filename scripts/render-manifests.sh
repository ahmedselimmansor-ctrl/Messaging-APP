#!/usr/bin/env bash
#
# Render an overlay to applyable YAML.
#
# `kustomize build` does almost all of it. What it cannot do is substitute the
# project and environment identifiers, because they appear *inside* strings —
# `ENV-auth-service@PROJECT_ID.iam.gserviceaccount.com`, and the Secret Manager
# resource paths in each SecretProviderClass. Kustomize's replacements
# transformer works on whole field values, not substrings, so reaching those
# would mean one brittle replacement rule per occurrence.
#
# Hence this script. It is the only supported way to produce manifests for a
# cluster: `kubectl apply -k` on an overlay directly would apply the literal
# placeholders and leave every pod unable to fetch its secrets, with an error
# that names a project called "PROJECT_ID".
#
# Usage:
#   ./scripts/render-manifests.sh prod            # to stdout
#   ./scripts/render-manifests.sh prod | kubectl apply -f -
#
set -euo pipefail

ENV="${1:?usage: $0 <dev|staging|prod> [project-id]}"

case "${ENV}" in
  dev|staging|prod) ;;
  *) echo "error: environment must be dev, staging or prod (got '${ENV}')" >&2; exit 1 ;;
esac

# Default to the naming convention; allow an override for a project that does
# not follow it.
PROJECT_ID="${2:-messaging-${ENV}}"

OVERLAY="$(dirname "$0")/../deploy/k8s/overlays/${ENV}"
if [ ! -d "${OVERLAY}" ]; then
  echo "error: no overlay at ${OVERLAY}" >&2
  exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
  echo "error: kubectl is required (it provides kustomize)" >&2
  exit 1
fi

RENDERED="$(kubectl kustomize "${OVERLAY}")"

# The substitution.
#
# ENV- is anchored to a boundary so it matches both bare occurrences
# (ENV-auth-service@...) and embedded ones (messaging-ENV-jwt-signing-key),
# while leaving unrelated text alone.
OUT="$(printf '%s' "${RENDERED}" \
  | sed -e "s/PROJECT_ID/${PROJECT_ID}/g" \
        -e "s/\\bENV-/${ENV}-/g")"

# Fail loudly rather than shipping a half-substituted manifest. A placeholder
# that survives to the cluster produces a runtime permission error naming a
# project that does not exist, which is a long way from the cause.
if printf '%s' "${OUT}" | grep -nE 'PROJECT_ID|IMAGE_REPOSITORY|\bENV-' >&2; then
  echo "error: the lines above still contain placeholders after substitution" >&2
  exit 1
fi

printf '%s\n' "${OUT}"
