terraform {
  required_providers {
    aws = {
      source  = "aws"
      version = "5.35.0"
    }
  }
}

module "s3_bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.0"

  bucket = "test-bucket"
}