package sql

var terraformNoContainedDbAuthGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "SQLSERVER_2017_STANDARD"
 	region           = "us-central1"
 	settings {
 	    database_flags {
 		    name  = "contained database authentication"
 		    value = "off"
 		}
 	}
 }
 			`,
}

var terraformNoContainedDbAuthBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "SQLSERVER_2017_STANDARD"
 	region           = "us-central1"
 }
 			`,
}

var terraformNoContainedDbAuthLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`,
}

var terraformNoContainedDbAuthRemediationMarkdown = ``
