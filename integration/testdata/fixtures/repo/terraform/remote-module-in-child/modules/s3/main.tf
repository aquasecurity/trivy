variable "bucket" {
	type = string
}

module "bucket" {
  source = "github.com/terraform-aws-modules/terraform-aws-s3-bucket?ref=v5.2.0"
  bucket = var.bucket
}