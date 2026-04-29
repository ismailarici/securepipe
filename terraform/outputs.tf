output "role_arn" {
  description = "ARN of the IAM role. Set this as AWS_ROLE_ARN in your app repo secrets."
  value       = aws_iam_role.github_actions.arn
}

output "ecr_repository_url" {
  description = "ECR repository URL. Use this as the image-name input (without the tag)."
  value       = aws_ecr_repository.app.repository_url
}

output "oidc_provider_arn" {
  description = "ARN of the GitHub OIDC provider. Shared across all roles in this account."
  value       = aws_iam_openid_connect_provider.github.arn
}

output "aws_account_id" {
  description = "AWS account ID. Set this as AWS_ACCOUNT_ID in your app repo secrets."
  value       = data.aws_caller_identity.current.account_id
}
