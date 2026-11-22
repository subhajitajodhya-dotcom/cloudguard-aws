# Run this ONCE, from your own PC, before the main stack.
# It creates: (1) a private S3 bucket for Terraform state, and
#             (2) a role GitHub Actions can assume WITHOUT any stored AWS keys (OIDC).

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "github_repo" {
  description = "GitHub repo allowed to deploy, in the form owner/name"
  type        = string
  default     = "subhajitajodhya-dotcom/cloudguard-aws"
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "me" {}

locals {
  state_bucket = "cloudguard-tfstate-${data.aws_caller_identity.me.account_id}"
}

resource "aws_s3_bucket" "state" {
  bucket = local.state_bucket
  force_destroy = true # learning project: lets the bootstrap be destroyed cleanly
  tags          = { Project = "cloudguard" }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lock table: stops two applies from running at the same time.
resource "aws_dynamodb_table" "lock" {
  name         = "cloudguard-tf-lock"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  attribute {
    name = "LockID"
    type = "S"
  }
}

# ---- GitHub Actions login (OIDC) ----

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

data "aws_iam_policy_document" "github_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Only the main branch of YOUR repo (and its pull requests) can use this role.
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_repo}:ref:refs/heads/main",
        "repo:${var.github_repo}:pull_request",
      ]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  name               = "cloudguard-github-deploy"
  assume_role_policy = data.aws_iam_policy_document.github_trust.json
}

# A deploy role needs wide rights because it creates IAM roles, Lambdas, APIs, etc.
# PowerUserAccess cannot manage IAM, so IAM is added separately and limited to
# roles/policies whose names start with "cloudguard-".
resource "aws_iam_role_policy_attachment" "github_power" {
  role       = aws_iam_role.github_deploy.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

data "aws_iam_policy_document" "github_iam" {
  statement {
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:UpdateRole", "iam:PassRole",
      "iam:TagRole", "iam:UntagRole", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole", "iam:PutRolePolicy", "iam:GetRolePolicy",
      "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy",
      "iam:UpdateAssumeRolePolicy",
    ]
    resources = ["arn:aws:iam::${data.aws_caller_identity.me.account_id}:role/cloudguard-*"]
  }
}

resource "aws_iam_role_policy" "github_iam" {
  name   = "cloudguard-iam-limited"
  role   = aws_iam_role.github_deploy.id
  policy = data.aws_iam_policy_document.github_iam.json
}

output "state_bucket" {
  value = aws_s3_bucket.state.id
}

output "github_deploy_role_arn" {
  value = aws_iam_role.github_deploy.arn
}
