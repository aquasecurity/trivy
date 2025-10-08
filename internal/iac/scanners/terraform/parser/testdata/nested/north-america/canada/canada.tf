variable "prefix" {
  type = string
  default = ""
}

output "name" {
  value = "${var.prefix}canada"
}

module "ontario-springfield" {
  source = "./springfield"
  prefix = "ontario-"
}

output "ontario-springfield" {
  value = module.ontario-springfield.name
}
