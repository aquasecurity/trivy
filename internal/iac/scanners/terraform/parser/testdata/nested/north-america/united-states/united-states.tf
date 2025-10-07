variable "prefix" {
  type = string
  default = ""
}

output "name" {
  value = "${var.prefix}united-states"
}

// Same module twice, with different variables
module "illinois-springfield" {
  source = "./springfield"
  prefix = "illinois-"
}

output "illinois-springfield" {
  value = module.illinois-springfield.name
}

module "idaho-springfield" {
  source = "./springfield"
  prefix = "idaho-"
}

output "idaho-springfield" {
  value = module.idaho-springfield.name
}

module "new-york" {
  source = "./new-york"
  prefix = ""
}

output "new-york" {
  value = module.new-york.name
}


