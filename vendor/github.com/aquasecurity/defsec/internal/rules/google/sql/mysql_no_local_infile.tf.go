package sql

var terraformMysqlNoLocalInfileGoodExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "MYSQL_5_6"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "local_infile"
 			value = "off"
 		}
 	}
 }
 			`,
}

var terraformMysqlNoLocalInfileBadExamples = []string{
	`
 resource "google_sql_database_instance" "db" {
 	name             = "db"
 	database_version = "MYSQL_5_6"
 	region           = "us-central1"
 	settings {
 		database_flags {
 			name  = "local_infile"
 			value = "on"
 		}
 	}
 }
 			`,
}

var terraformMysqlNoLocalInfileLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`, `https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html`,
}

var terraformMysqlNoLocalInfileRemediationMarkdown = ``
