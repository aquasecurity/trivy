variable "prefix" {
    type = string
    default = ""
}

output "name" {
  value = "${var.prefix}north-america"
}

module "canada" {
  source = "./canada"
  prefix = ""
}

module "united-states" {
  source = "./united-states"
  prefix = ""
}

output "united-states" {
  value = module.united-states.name
}