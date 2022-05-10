package sql

var terraformPgLogConnectionsGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_connections"
 			value = "on"
 		}
 	}
 }
 			`,
}

var terraformPgLogConnectionsBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_connections"
 			value = "off"
 		}
 	}
 }
 			`,
}

var terraformPgLogConnectionsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`,
}

var terraformPgLogConnectionsRemediationMarkdown = ``
