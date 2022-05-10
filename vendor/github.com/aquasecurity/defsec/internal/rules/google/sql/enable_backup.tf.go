package sql

var terraformEnableBackupGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		backup_configuration {
 			enabled = true
 		}
 	}
 }
 			`,
}

var terraformEnableBackupBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "POSTGRES_12"
 	region           = "us-central1"
 	settings {
 		backup_configuration {
 			enabled = false
 		}
 	}
 }
 			`,
}

var terraformEnableBackupLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance#settings.backup_configuration.enabled=true`,
}

var terraformEnableBackupRemediationMarkdown = ``
