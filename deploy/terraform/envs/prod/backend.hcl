# terraform init -backend-config=envs/prod/backend.hcl
#
# The state bucket must exist before the first init, with versioning on:
#   gsutil mb -l europe-west1 gs://messaging-tfstate-prod
#   gsutil versioning set on gs://messaging-tfstate-prod
bucket = "messaging-tfstate-prod"
prefix = "messaging/prod"
