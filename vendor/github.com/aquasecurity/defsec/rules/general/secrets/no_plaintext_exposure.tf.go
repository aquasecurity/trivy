package secrets

var terraformNoPlaintextExposureGoodExamples = []string{
	`
 variable "password" {
   description = "The root password for our VM"
   type        = string
 }
 
 resource "evil_corp" "virtual_machine" {
 	root_password = var.password
 }
 `,
}

var terraformNoPlaintextExposureBadExamples = []string{
	`
 variable "password" {
   description = "The root password for our VM"
   type        = string
   default     = "p4ssw0rd"
 }
 
 resource "evil_corp" "virtual_machine" {
 	root_password = var.password
 }
 `,
}

var terraformNoPlaintextExposureLinks = []string{
	`https://www.terraform.io/docs/state/sensitive-data.html`,
}

var terraformNoPlaintextExposureRemediationMarkdown = ``
