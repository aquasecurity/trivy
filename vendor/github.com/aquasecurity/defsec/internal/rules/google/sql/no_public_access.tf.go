package sql

var terraformNoPublicAccessGoodExamples = []string{
	`
 resource "google_sql_database_instance" "postgres" {
 	name             = "postgres-instance-a"
 	database_version = "POSTGRES_11"
 	
 	settings {
 		tier = "db-f1-micro"
 	
 		ip_configuration {
 			ipv4_enabled = false
 			authorized_networks {
 				value           = "10.0.0.1/24"
 				name            = "internal"
 			}
 		}
 	}
 }
 			`,
}

var terraformNoPublicAccessBadExamples = []string{
	`
 resource "google_sql_database_instance" "postgres" {
 	name             = "postgres-instance-a"
 	database_version = "POSTGRES_11"
 	
 	settings {
 		tier = "db-f1-micro"
 	
 		ip_configuration {
 			ipv4_enabled = false
 			authorized_networks {
 				value           = "108.12.12.0/24"
 				name            = "internal"
 			}
 	
 			authorized_networks {
 				value           = "0.0.0.0/0"
 				name            = "internet"
 			}
 		}
 	}
 }
 			`,
}

var terraformNoPublicAccessLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance`,
}

var terraformNoPublicAccessRemediationMarkdown = ``
