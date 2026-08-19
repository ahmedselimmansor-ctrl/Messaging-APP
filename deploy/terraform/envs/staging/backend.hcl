# terraform init -backend-config=envs/staging/backend.hcl
#
# The state bucket must exist before the first init, with versioning on:
#   gsutil mb -l europe-west1 gs://messaging-tfstate-staging
#   gsutil versioning set on gs://messaging-tfstate-staging
bucket = "messaging-tfstate-staging"
prefix = "messaging/staging"
