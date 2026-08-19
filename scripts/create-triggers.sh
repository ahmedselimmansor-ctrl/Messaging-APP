#!/usr/bin/env bash
#
# Creates the Cloud Build triggers.
#
# The critical detail is --included-files. Without it, every push rebuilds all
# nine services, which is slow, expensive, and produces nine new images where
# one changed. With it, a change to services/chat-service rebuilds only the
# chat service — and a change to pkg/ correctly rebuilds everything, because
# every service's include list also covers the shared packages.
#
# Usage:
#   ./scripts/create-triggers.sh PROJECT_ID GITHUB_OWNER GITHUB_REPO [REGION]

set -euo pipefail

PROJECT_ID="${1:?usage: $0 PROJECT_ID GITHUB_OWNER GITHUB_REPO [REGION]}"
GH_OWNER="${2:?github owner is required}"
GH_REPO="${3:?github repo is required}"
REGION="${4:-europe-west1}"

# Every service, with the path under services/ that holds its main package.
# The consumers live one level deeper, which is why the two are separate
# fields rather than one.
declare -A SERVICES=(
  [auth-service]="auth-service"
  [chat-service]="chat-service"
  [realtime-gateway]="realtime-gateway"
  [presence-service]="presence-service"
  [media-service]="media-service"
  [notification-service]="notification-service"
  [persister]="consumers/persister"
  [pusher]="consumers/pusher"
  [indexer]="consumers/indexer"
  [search-service]="search-service"
  [call-service]="call-service"
  [mediaproc]="consumers/mediaproc"
  [auditor]="consumers/auditor"
  [admin-service]="admin-service"
)

# Shared paths that must rebuild everything when they change.
SHARED_PATHS="pkg/**,go.mod,go.sum,build/Dockerfile"

echo "creating triggers in ${PROJECT_ID} (${REGION}) for ${GH_OWNER}/${GH_REPO}"

# ---------------------------------------------------------------------------
# Pull requests: validate, do not build
# ---------------------------------------------------------------------------

gcloud builds triggers create github \
  --name="pr-validate" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --repo-name="${GH_REPO}" \
  --repo-owner="${GH_OWNER}" \
  --pull-request-pattern="^(main|develop)$" \
  --comment-control=COMMENTS_ENABLED_FOR_EXTERNAL_CONTRIBUTORS_ONLY \
  --build-config="deploy/cloudbuild/pr-validate.yaml" \
  --description="Build, test, lint and validate manifests on every pull request" \
  || echo "  pr-validate already exists"

# ---------------------------------------------------------------------------
# Per-service build triggers on main
# ---------------------------------------------------------------------------

for service in "${!SERVICES[@]}"; do
  path="${SERVICES[$service]}"

  gcloud builds triggers create github \
    --name="build-${service}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --repo-name="${GH_REPO}" \
    --repo-owner="${GH_OWNER}" \
    --branch-pattern="^main$" \
    --build-config="deploy/cloudbuild/service.yaml" \
    --included-files="services/${path}/**,${SHARED_PATHS}" \
    --substitutions="_SERVICE=${service},_SERVICE_PATH=${path},_REGION=${REGION},_ENV=staging" \
    --description="Build, scan, attest and release ${service}" \
    || echo "  build-${service} already exists"

  echo "  build-${service}: services/${path}/** plus shared"
done

# ---------------------------------------------------------------------------
# Migration image
# ---------------------------------------------------------------------------

gcloud builds triggers create github \
  --name="build-migrate" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --repo-name="${GH_REPO}" \
  --repo-owner="${GH_OWNER}" \
  --branch-pattern="^main$" \
  --build-config="deploy/cloudbuild/migrate.yaml" \
  --included-files="db/**,build/Dockerfile.migrate" \
  --substitutions="_REGION=${REGION}" \
  --description="Build the migration runner when the schema changes" \
  || echo "  build-migrate already exists"

# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------
#
# Terraform is validated in CI but never applied by it. An automated apply
# that can create and destroy databases is a very large amount of authority to
# hand a pipeline; a human runs the apply after reading the plan.

gcloud builds triggers create github \
  --name="validate-terraform" \
  --project="${PROJECT_ID}" \
  --region="${REGION}" \
  --repo-name="${GH_REPO}" \
  --repo-owner="${GH_OWNER}" \
  --branch-pattern=".*" \
  --build-config="deploy/cloudbuild/pr-validate.yaml" \
  --included-files="deploy/terraform/**" \
  --description="Validate Terraform on any branch; apply is manual" \
  || echo "  validate-terraform already exists"

cat <<EOF

Triggers created.

Two things are deliberately not automated:

  1. Terraform apply. CI validates the configuration; a human reads the plan
     and applies it. A pipeline that can destroy a production database is
     more authority than a pipeline should hold.

  2. Production promotion. Cloud Build creates a release and Cloud Deploy
     promotes it to staging automatically, but the production target has
     requireApproval: true. Approve with:

       gcloud deploy rollouts approve ROLLOUT \\
         --project=${PROJECT_ID} --region=${REGION} \\
         --delivery-pipeline=messaging-pipeline --release=RELEASE

Enable build approval on the production triggers as well if you want a second
gate before the image is even built:

  gcloud builds triggers update TRIGGER --require-approval
EOF
