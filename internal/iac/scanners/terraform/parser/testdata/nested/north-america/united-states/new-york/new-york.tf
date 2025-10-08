variable "prefix" {
  type = string
  default = ""
}

output "name" {
  value = "${var.prefix}new-york"
}

module "new-york-city" {
  source = "./new-york-city"
  prefix = ""
}

output "new-york-city" {
  value = module.new-york-city.name
}
