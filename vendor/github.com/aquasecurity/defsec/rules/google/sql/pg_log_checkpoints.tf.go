package sql

var terraformPgLogCheckpointsGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_checkpoints"
 			value = "on"
 		}
 	}
 }
 			`,
}

var terraformPgLogCheckpointsBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "log_checkpoints"
 			value = "off"
 		}
 	}
 }
 			`,
}

var terraformPgLogCheckpointsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`,
}

var terraformPgLogCheckpointsRemediationMarkdown = ``
