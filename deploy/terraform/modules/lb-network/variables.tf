variable "project_id" { type = string }
variable "region" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }

variable "domain" { type = string }
variable "dns_zone_name" { type = string }

variable "mtproto_hostname" {
  type    = string
  default = "mt"
}

variable "instance_groups" {
  description = "Self links of the managed instance groups backing the realtime node pool. Read from the GKE node pool after it exists."
  type        = list(string)
  default     = []
}

variable "enable_advanced_ddos" {
  description = "Advanced Network DDoS Protection. Paid; worth it for prod."
  type        = bool
  default     = false
}
