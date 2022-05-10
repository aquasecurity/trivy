package sql

var terraformPgLogLockWaitsGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_lock_waits"
 			value = "on"
 		}
 	}
 }
 			`,
}

var terraformPgLogLockWaitsBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_lock_waits"
 			value = "off"
 		}
 	}
 }
 			`,
}

var terraformPgLogLockWaitsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`,
}

var terraformPgLogLockWaitsRemediationMarkdown = ``
