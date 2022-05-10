package sql

var terraformPgLogErrorsGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_min_messages"
 			value = "WARNING"
 		}
 	}
 }
 			`,
}

var terraformPgLogErrorsBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_min_messages"
 			value = "PANIC"
 		}
 	}
 }
 			`,
}

var terraformPgLogErrorsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`,
}

var terraformPgLogErrorsRemediationMarkdown = ``
