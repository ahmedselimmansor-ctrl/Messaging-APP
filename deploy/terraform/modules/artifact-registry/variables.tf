variable "project_id" { type = string }
variable "region" { type = string }
variable "env" { type = string }
variable "name_prefix" { type = string }

variable "repository_id" {
  type    = string
  default = "messaging-app"
}

variable "node_service_account" { type = string }
variable "cloudbuild_service_account" { type = string }

variable "labels" {
  type    = map(string)
  default = {}
}
