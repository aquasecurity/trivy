resource "aws_s3_bucket" "one" {

}

module "module_in_nested_dir" {
  source = "./nested/"
}