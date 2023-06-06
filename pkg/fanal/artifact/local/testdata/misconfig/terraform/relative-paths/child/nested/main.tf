resource "aws_s3_bucket" "two" {

}

module "module_in_parent_dir" {
  source = "../../parent/"
}