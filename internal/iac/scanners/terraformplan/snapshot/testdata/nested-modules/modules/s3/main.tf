resource "aws_s3_bucket" "this" {
  
}

module "s3_log" {
  source = "./modules/logging"
  bucket = aws_s3_bucket.this.id
}