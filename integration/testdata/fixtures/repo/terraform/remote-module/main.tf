module "bucket" {
  source = "terraform-aws-modules/s3-bucket/aws"
  version = "5.2.0"
  bucket = "test"
}