package compute

var terraformUseSecureTlsPolicyGoodExamples = []string{
	`
 resource "google_compute_ssl_policy" "good_example" {
   name    = "production-ssl-policy"
   profile = "MODERN"
   min_tls_version = "TLS_1_2"
 }
 `,
}

var terraformUseSecureTlsPolicyBadExamples = []string{
	`
 resource "google_compute_ssl_policy" "bad_example" {
   name    = "production-ssl-policy"
   profile = "MODERN"
   min_tls_version = "TLS_1_1"
 }
 
 `,
}

var terraformUseSecureTlsPolicyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_ssl_policy#min_tls_version`,
}

var terraformUseSecureTlsPolicyRemediationMarkdown = ``
