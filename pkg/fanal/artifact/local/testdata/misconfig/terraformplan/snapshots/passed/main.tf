terraform {
  required_providers {
    aws = {
      source  = "aws"
      version = "5.35.0"
    }
  }
}

resource "aws_s3_bucket" "this" {
    bucket = "test-bucket"
}
