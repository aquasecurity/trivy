package sql

var terraformNoCrossDbOwnershipChainingGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "SQLSERVER_2017_STANDARD"
 	region           = "us-central1"
 	settings {
 	    database_flags {
 		    name  = "cross db ownership chaining"
 		    value = "off"
 		}
 	}
 }
 			`,
}

var terraformNoCrossDbOwnershipChainingBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "SQLSERVER_2017_STANDARD"
 	region           = "us-central1"
 }
 			`,
}

var terraformNoCrossDbOwnershipChainingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`,
}

var terraformNoCrossDbOwnershipChainingRemediationMarkdown = ``
