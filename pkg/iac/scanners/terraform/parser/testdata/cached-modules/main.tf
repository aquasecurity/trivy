module "s3-bucket" {
  source  = "my-private-module/s3-bucket/aws"
  version = "1.0.0"
  bucket = "my-s3-bucket"
}