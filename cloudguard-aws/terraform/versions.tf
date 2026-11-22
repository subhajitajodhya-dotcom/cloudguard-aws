terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Bucket name is passed at init time (see README):
  #   terraform init -backend-config="bucket=cloudguard-tfstate-<ACCOUNT_ID>"
  backend "s3" {
    key            = "cloudguard/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "cloudguard-tf-lock"
    encrypt        = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "cloudguard"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "me" {}
