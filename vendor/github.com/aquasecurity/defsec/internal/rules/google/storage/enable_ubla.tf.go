package storage

var terraformEnableUblaGoodExamples = []string{
	`
 resource "google_storage_bucket" "static-site" {
 	name          = "image-store.com"
 	location      = "EU"
 	force_destroy = true
 	
 	uniform_bucket_level_access = true
 	
 	website {
 		main_page_suffix = "index.html"
 		not_found_page   = "404.html"
 	}
 	cors {
 		origin          = ["http://image-store.com"]
 		method          = ["GET", "HEAD", "PUT", "POST", "DELETE"]
 		response_header = ["*"]
 		max_age_seconds = 3600
 	}
 }
 `,
}

var terraformEnableUblaBadExamples = []string{
	`
 resource "google_storage_bucket" "static-site" {
 	name          = "image-store.com"
 	location      = "EU"
 	force_destroy = true
 	
 	uniform_bucket_level_access = false
 	
 	website {
 		main_page_suffix = "index.html"
 		not_found_page   = "404.html"
 	}
 	cors {
 		origin          = ["http://image-store.com"]
 		method          = ["GET", "HEAD", "PUT", "POST", "DELETE"]
 		response_header = ["*"]
 		max_age_seconds = 3600
 	}
 }
 `,
}

var terraformEnableUblaLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/storage_bucket#uniform_bucket_level_access`,
}

var terraformEnableUblaRemediationMarkdown = ``
