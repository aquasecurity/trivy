package config.type

# Kubernetes
detect[type] {
   input.apiVersion != ""
   input.kind != ""
   input.metadata != ""
   input.spec != ""
   type := "kubernetes"
}

# AWS CloudFormation
detect[type] {
   input.AWSTemplateFormatVersion != ""
   type := "cloudformation"
}

# Ansible Playbook
detect[type] {
   count(input) > 0
   count({x |
       input[x].name != "";
       input[x].hosts != "";
       input[x].tasks != ""
   }) == count(input)
   type := "ansible"
}
