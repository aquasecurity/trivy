package msk

var terraformEnableInTransitEncryptionGoodExamples = []string{
	`
 resource "aws_msk_cluster" "good_example" {
 	encryption_info {
 		encryption_in_transit {
 			client_broker = "TLS"
 			in_cluster = true
 		}
 	}
 }
 `,
}

var terraformEnableInTransitEncryptionBadExamples = []string{
	`
 resource "aws_msk_cluster" "bad_example" {
 	encryption_info {
 		encryption_in_transit {
 			client_broker = "TLS_PLAINTEXT"
 			in_cluster = true
 		}
 	}
 }
 `,
}

var terraformEnableInTransitEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference`,
}

var terraformEnableInTransitEncryptionRemediationMarkdown = ``
