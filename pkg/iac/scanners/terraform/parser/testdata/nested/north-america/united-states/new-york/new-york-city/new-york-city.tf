variable "prefix" {
  type = string
  default = ""
}

output "name" {
  value = "${var.prefix}new-york-city"
}