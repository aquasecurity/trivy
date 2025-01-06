package rego

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetProviderNames(t *testing.T) {
	assert.Equal(t, []string{"AWS", "Azure", "Cloudstack", "Digital Ocean", "Dockerfile", "GitHub", "Google", "Kubernetes", "Nifcloud", "OpenStack", "Oracle"}, GetProviderNames())
}

func TestGetProviderServiceNames(t *testing.T) {
	testCases := []struct {
		provider         string
		expectedServices []string
	}{
		{
			provider:         "aws",
			expectedServices: []string{"apigateway", "athena", "cloudfront", "cloudtrail", "cloudwatch", "codebuild", "config", "documentdb", "dynamodb", "ec2", "ecr", "ecs", "efs", "eks", "elasticache", "elasticsearch", "elb", "emr", "iam", "kinesis", "kms", "lambda", "mq", "msk", "neptune", "rds", "redshift", "s3", "sam", "sns", "sqs", "ssm", "workspaces"},
		},
		{
			provider:         "azure",
			expectedServices: []string{"appservice", "authorization", "compute", "container", "database", "datafactory", "datalake", "keyvault", "monitor", "network", "security-center", "storage", "synapse"},
		},
		{
			provider:         "digital ocean",
			expectedServices: []string{"compute", "spaces"},
		},
		{
			provider:         "dockerfile",
			expectedServices: []string{"general"},
		},
		{
			provider:         "google",
			expectedServices: []string{"bigquery", "compute", "dns", "gke", "iam", "kms", "sql", "storage"},
		},
		{
			provider:         "kubernetes",
			expectedServices: []string{"general", "network"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.provider, func(t *testing.T) {
			assert.Equal(t, tc.expectedServices, GetProviderServiceNames(tc.provider))
		})
	}

}
