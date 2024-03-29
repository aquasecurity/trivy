resource "aws_s3_bucket_versioning" "this" {
  bucket = var.bucket
  versioning_configuration {
    status = "Enabled"
  }
}

variable "bucket" {
  type = string
}
