resource "aws_s3_bucket" "one" {

 }

 resource "aws_s3_bucket" "two" {

 }

 module "module_in_parent_dir" {
   source = "../does not exist anywhere/"
}