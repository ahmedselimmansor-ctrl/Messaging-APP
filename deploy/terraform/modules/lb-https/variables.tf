variable "project_id" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }

variable "domain" { type = string }
variable "api_hostname" { type = string }
variable "cdn_hostname" { type = string }
variable "dns_zone_name" { type = string }

variable "domains" {
  description = "Every hostname the managed certificate should cover."
  type        = list(string)
}

variable "cdn_domain" {
  description = "Full hostname routed to the CDN backend bucket."
  type        = string
}

variable "cdn_backend_bucket_id" { type = string }

variable "neg_name" {
  description = "Name of the zonal NEG the GKE Gateway controller created. Empty on the first apply, before the cluster exists."
  type        = string
  default     = ""
}

variable "neg_zone" {
  type    = string
  default = ""
}

variable "blocked_regions" {
  description = "ISO 3166-1 alpha-2 codes to deny at the edge. Empty in normal operation; used during a targeted attack."
  type        = list(string)
  default     = []
}
