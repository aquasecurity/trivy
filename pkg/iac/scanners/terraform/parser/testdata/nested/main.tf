module "north-america" {
  source = "./north-america"
}

output "all" {
  value = [
    module.north-america,
  ]
}