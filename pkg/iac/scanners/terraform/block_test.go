package terraform

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IsPresentCheckOnBlock(t *testing.T) {
	tests := []struct {
		name              string
		source            string
		expectedAttribute string
	}{
		{
			name: "expected attribute is present",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
}`,
			expectedAttribute: "bucket_name",
		},
		{
			name: "expected acl attribute is present",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
}`,
			expectedAttribute: "acl",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := createModulesFromSource(t, test.source, ".tf")
			for _, module := range modules {
				for _, block := range module.GetBlocks() {
					assert.NotNil(t, block.GetAttribute(test.expectedAttribute))
				}
			}
		})
	}
}

func Test_IsNotPresentCheckOnBlock(t *testing.T) {
	tests := []struct {
		name              string
		source            string
		expectedAttribute string
	}{
		{
			name: "expected attribute is not present",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	
}`,
			expectedAttribute: "acl",
		},
		{
			name: "expected acl attribute is not present",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
	
}`,
			expectedAttribute: "logging",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := createModulesFromSource(t, test.source, ".tf")
			for _, module := range modules {
				for _, block := range module.GetBlocks() {
					assert.Nil(t, block.GetAttribute(test.expectedAttribute))
				}
			}
		})
	}
}
