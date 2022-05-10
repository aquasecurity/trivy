package sql

var terraformEnablePgTempFileLoggingGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 	    database_flags {
 		    name  = "log_temp_files"
 		    value = "0"
 		}
 	}
 }
 			`,
}

var terraformEnablePgTempFileLoggingBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 }
 			`,
}

var terraformEnablePgTempFileLoggingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`,
}

var terraformEnablePgTempFileLoggingRemediationMarkdown = ``
