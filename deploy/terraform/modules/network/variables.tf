variable "project_id" { type = string }
variable "region" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }
variable "domain" { type = string }

variable "subnet_cidr" { type = string }
variable "pods_cidr" { type = string }
variable "services_cidr" { type = string }
variable "master_cidr" { type = string }

variable "psc_cidr" {
  description = "CIDR for Private Service Connect endpoints. A /24 is ample; each endpoint takes one address."
  type        = string
  default     = "10.30.0.0/24"
}

variable "nat_ip_count" {
  description = "Reserved NAT addresses. Each supports roughly 64k concurrent connections per destination; two gives headroom and lets one be rotated without an outage."
  type        = number
  default     = 2
}

variable "routing_mode" {
  description = "REGIONAL or GLOBAL. GLOBAL is required before a second region can be added; switching later is a live change to the VPC and is best done up front."
  type        = string
  default     = "GLOBAL"

  validation {
    condition     = contains(["REGIONAL", "GLOBAL"], var.routing_mode)
    error_message = "routing_mode must be REGIONAL or GLOBAL."
  }
}
