package sql

var terraformPgNoMinStatementLoggingGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_min_duration_statement"
 			value = "-1"
 		}
 	}
 }
 			`,
}

var terraformPgNoMinStatementLoggingBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_min_duration_statement"
 			value = "99"
 		}
 	}
 }
 			`,
}

var terraformPgNoMinStatementLoggingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`,
}

var terraformPgNoMinStatementLoggingRemediationMarkdown = ``
