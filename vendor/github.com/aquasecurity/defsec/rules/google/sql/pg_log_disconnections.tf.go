package sql

var terraformPgLogDisconnectionsGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_disconnections"
 			value = "on"
 		}
 	}
 }
 			`,
}

var terraformPgLogDisconnectionsBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_disconnections"
 			value = "off"
 		}
 	}
 }
 			`,
}

var terraformPgLogDisconnectionsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`,
}

var terraformPgLogDisconnectionsRemediationMarkdown = ``
