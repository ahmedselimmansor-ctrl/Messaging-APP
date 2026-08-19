variable "project_id" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }

variable "bucket_location" {
  description = "Bucket location. A multi-region (EU, US) survives a regional outage; a single region is cheaper and keeps data in one jurisdiction."
  type        = string
  default     = "EU"
}

variable "kms_key_id" {
  description = "CMEK for the private media bucket."
  type        = string
}

variable "cors_origins" {
  description = "Origins allowed to PUT to a signed upload URL from a browser."
  type        = list(string)
  default     = []
}

variable "labels" {
  type    = map(string)
  default = {}
}

variable "audit_retention_days" {
  description = "How long audit records are retained. Once the policy is locked this cannot be reduced, so pick the longest obligation that applies."
  type        = number
  default     = 2555 # seven years

  validation {
    condition     = var.audit_retention_days >= 365
    error_message = "audit_retention_days must be at least 365; a trail shorter than a year cannot answer questions asked a year later."
  }
}

variable "audit_retention_locked" {
  description = "Lock the audit bucket's retention policy. IRREVERSIBLE — once applied the retention period can never be shortened and objects cannot be deleted before it expires, by anyone. Enable in prod; leave off in dev."
  type        = bool
  default     = false
}
