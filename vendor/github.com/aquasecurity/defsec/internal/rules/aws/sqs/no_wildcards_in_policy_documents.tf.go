package sqs

var terraformNoWildcardsInPolicyDocumentsGoodExamples = []string{
	`
 resource "aws_sqs_queue_policy" "good_example" {
   queue_url = aws_sqs_queue.q.id
 
   policy = <<POLICY
 {
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "sqs:SendMessage"
     }
   ]
 }
 POLICY
 }
 `,
}

var terraformNoWildcardsInPolicyDocumentsBadExamples = []string{
	`
 resource "aws_sqs_queue_policy" "bad_example" {
   queue_url = aws_sqs_queue.q.id
 
   policy = <<POLICY
 {
   "Statement": [
     {
       "Effect": "Allow",
       "Principal": "*",
       "Action": "*"
     }
   ]
 }
 POLICY
 }
 `,
}

var terraformNoWildcardsInPolicyDocumentsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sqs_queue_policy`,
}

var terraformNoWildcardsInPolicyDocumentsRemediationMarkdown = ``
