variable "project_id" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }
variable "network_id" { type = string }

variable "primary_region" { type = string }
variable "primary_mtproto_ip" {
  description = "The primary region's MTProto address, from the lb-network module."
  type        = string
}

variable "secondary_region" {
  description = "The region to add. Pick for user proximity, not for cost: the whole point is terminating connections near people."
  type        = string
}

variable "secondary_subnet_cidr" {
  description = "Must not overlap the primary region's ranges — they share one VPC."
  type        = string
}
variable "secondary_pods_cidr" { type = string }
variable "secondary_services_cidr" { type = string }

variable "secondary_instance_groups" {
  description = "Managed instance groups for the secondary region's realtime pool. Populated on the second apply, as in the primary region."
  type        = list(string)
  default     = []
}

variable "domain" { type = string }
variable "dns_zone_name" { type = string }
variable "mtproto_hostname" {
  type    = string
  default = "mt"
}

variable "nat_ip_count" {
  type    = number
  default = 2
}

variable "alert_notification_channels" {
  type    = list(string)
  default = []
}
