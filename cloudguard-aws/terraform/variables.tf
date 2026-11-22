variable "region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  description = "dev or prod. Used in every resource name."
  type        = string
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be dev or prod."
  }
}

variable "alert_email" {
  description = "Email that receives alerts about new HIGH or CRITICAL findings."
  type        = string
}

variable "lambda_zip" {
  description = "Path to the zip made by scripts/package.sh"
  type        = string
  default     = "../build/lambda.zip"
}

variable "scan_schedule" {
  description = "EventBridge schedule for automatic scans."
  type        = string
  default     = "rate(1 day)"
}

variable "schedule_enabled" {
  type    = bool
  default = false
}

variable "scan_regions" {
  description = "Regions to scan for regional rules (for example network rules)."
  type        = list(string)
  default     = ["us-east-1"]
}

variable "allowed_role_arns" {
  description = "Roles in OTHER accounts that scans may assume. Empty = only this account."
  type        = list(string)
  default     = []
}

variable "log_retention_days" {
  type    = number
  default = 14
}
