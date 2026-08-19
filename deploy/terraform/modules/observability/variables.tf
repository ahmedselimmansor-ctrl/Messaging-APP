variable "project_id" { type = string }
variable "region" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }

variable "k8s_namespace" {
  type    = string
  default = "messaging"
}

variable "alert_email" {
  description = "Address for alerts. Empty disables every alert policy."
  type        = string
  default     = ""
}

variable "expected_min_connections" {
  description = "Floor for live realtime connections. Below this, something is wrong at the network layer. Set from observed baseline, not from capacity."
  type        = number
  default     = 100
}
