# terraform init -backend-config=envs/dev/backend.hcl
#
# The state bucket must exist before the first init, with versioning on:
#   gsutil mb -l europe-west1 gs://messaging-tfstate-dev
#   gsutil versioning set on gs://messaging-tfstate-dev
bucket = "messaging-tfstate-dev"
prefix = "messaging/dev"
