variable "domain_name" {
  description = "Primary domain (e.g., simtkus.com)"
  type        = string
}

variable "hosted_zone_id" {
  description = "Route53 Hosted Zone ID"
  type        = string
}

variable "region" {
  description = "AWS region for most resources"
  type        = string
  default     = "us-east-1"
}

variable "profile" {
  description = "AWS CLI profile name (optional)"
  type        = string
  default     = null
}

