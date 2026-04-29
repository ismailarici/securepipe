variable "github_org" {
  description = "GitHub organisation or username that owns the app repository"
  type        = string
}

variable "github_repo" {
  description = "App repository name (without the org prefix)"
  type        = string
}

variable "aws_region" {
  description = "AWS region to create resources in"
  type        = string
  default     = "us-east-1"
}

variable "ecr_repo_name" {
  description = "Name of the ECR repository to create. Defaults to the app repo name."
  type        = string
  default     = ""
}

variable "role_name" {
  description = "Name of the IAM role that GitHub Actions will assume"
  type        = string
  default     = ""
}
