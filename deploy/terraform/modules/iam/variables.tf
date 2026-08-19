variable "project_id" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }

variable "k8s_namespace" {
  description = "Namespace the workloads run in. Part of the Workload Identity member string, so it must match the manifests exactly."
  type        = string
  default     = "messaging"
}

variable "secret_access" {
  description = "map of binding name -> {workload, secret_id}, granting one workload access to one secret."
  type = map(object({
    workload  = string
    secret_id = string
  }))
  default = {}
}
