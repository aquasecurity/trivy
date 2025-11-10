package terraform

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Test_AttributeContains(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     string
		expectedResult bool
		ignoreCase     bool
	}{
		{
			name: "bucket name contains Name",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
}`,
			checkAttribute: "bucket_name",
			checkValue:     "etNa",
			expectedResult: true,
		},
		{
			name: "bucket acl doesn't contain private",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
}`,
			checkAttribute: "acl",
			checkValue:     "private",
			expectedResult: false,
		},
		{
			name: "tags attribute is a map with a Department key",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
	tags = {
		Department = "Finance"
	}
}`,
			checkAttribute: "tags",
			checkValue:     "Department",
			expectedResult: true,
		},
		{
			name: "cidr_block has expected subnet",
			source: `
resource "aws_security_group" "my-security_group" {
	cidr_block = ["10.0.0.0/16", "172.0.0.0/8" ] 
}`,
			checkAttribute: "cidr_block",
			checkValue:     "172.0.0.0/8",
			expectedResult: true,
		},
		{
			name: "autoscaling group has propagated key defined 1st tag is present",
			source: `
resource "aws_autoscaling_group" "my-aws_autoscaling_group" {		
	tags = [
		{
			"key"                 = "Name"
			"propagate_at_launch" = "true"
			"value"               = "couchbase-seb-develop-dev"
		},
		{
			"key"                 = "app"
			"propagate_at_launch" = "true"
			"value"               = "myapp"
		}
		]
}`,
			checkAttribute: "tags",
			checkValue:     "Name",
			expectedResult: true,
		},
		{
			name: "autoscaling group has propagated key defined 2nd tag is present",
			source: `
resource "aws_autoscaling_group" "my-aws_autoscaling_group" {		
	tags = [
		{
			"key"                 = "Name"
			"propagate_at_launch" = "true"
			"value"               = "couchbase-seb-develop-dev"
		},
		{
			"key"                 = "app"
			"propagate_at_launch" = "true"
			"value"               = "myapp"
		}
		]
}`,
			checkAttribute: "tags",
			checkValue:     "app",
			expectedResult: true,
		},
		{
			name: "autoscaling group has propagated key defined and tag is not present",
			source: `
resource "aws_autoscaling_group" "my-aws_autoscaling_group" {		
	tags = [
		{
			"key"                 = "Name"
			"propagate_at_launch" = "true"
			"value"               = "couchbase-seb-develop-dev"
		},
		{
			"key"                 = "app"
			"propagate_at_launch" = "true"
			"value"               = "myapp"
		}
		]
}`,
			checkAttribute: "tags",
			checkValue:     "NotThere",
			expectedResult: false,
		},
		{
			name: "contains array of strings ignores case",
			source: `
resource "aws_security_group" "my-security_group" {
	cidr_block = ["Foo", "Bar" ] 
}`,
			checkAttribute: "cidr_block",
			checkValue:     "foo",
			expectedResult: true,
			ignoreCase:     true,
		},
		{
			name: "contains array of strings without ignore case",
			source: `
resource "aws_security_group" "my-security_group" {
	cidr_block = ["Foo", "Bar" ] 
}`,
			checkAttribute: "cidr_block",
			checkValue:     "foo",
			expectedResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := createModulesFromSource(t, test.source, ".tf")
			for _, module := range modules {
				for _, b := range module.GetBlocks() {
					attr := b.GetAttribute(test.checkAttribute)
					require.NotNil(t, attr)
					if test.ignoreCase {
						assert.Equal(t, test.expectedResult, attr.Contains(test.checkValue, terraform.IgnoreCase))
					} else {
						assert.Equal(t, test.expectedResult, attr.Contains(test.checkValue))
					}
				}
			}
		})
	}
}

func Test_AttributeIsEmpty(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		checkValue     []any
		expectedResult bool
	}{
		{
			name: "bucket acl is not empty",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
}`,
			checkAttribute: "acl",
			expectedResult: false,
		},
		{
			name: "bucket acl is empty",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = ""
}`,
			checkAttribute: "acl",
			expectedResult: true,
		},
		{
			name: "tags is not empty",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
	tags = {
		Department = "Finance"
	}
}`,
			checkAttribute: "tags",
			expectedResult: false,
		},
		{
			name: "tags is empty",
			source: `
resource "aws_s3_bucket" "my-bucket" {
 	bucket_name = "bucketName"
	acl = "public-read"
	tags = {
	}
}`,
			checkAttribute: "tags",
			expectedResult: true,
		},
		{
			name: "cidr is not empty",
			source: `
resource "aws_security_group_rule" "example" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-123456"
}`,
			checkAttribute: "cidr_blocks",
			expectedResult: false,
		},
		{
			name: "cidr is empty",
			source: `
resource "aws_security_group_rule" "example" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = []
  security_group_id = "sg-123456"
}`,
			checkAttribute: "cidr_blocks",
			expectedResult: true,
		},
		{
			name: "from_port_is_not_empty",
			source: `
resource "aws_security_group_rule" "example" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = []
  security_group_id = "sg-123456"
}`,
			checkAttribute: "from_port",
			expectedResult: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := createModulesFromSource(t, test.source, ".tf")
			for _, module := range modules {
				for _, block := range module.GetBlocks() {
					attr := block.GetAttribute(test.checkAttribute)
					require.NotNil(t, attr)
					assert.Equal(t, test.expectedResult, attr.IsEmpty())
				}
			}
		})
	}
}

func Test_AttributeIsTrue(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		expectedResult bool
	}{
		{
			name: "check attribute is true",
			source: `
resource "boolean_something" "my-something" {
	value = true
}`,
			checkAttribute: "value",
			expectedResult: true,
		},
		{
			name: "check attribute as string is true",
			source: `
resource "boolean_something" "my-something" {
	value = "true"
}`,
			checkAttribute: "value",
			expectedResult: true,
		},
		{
			name: "check attribute as string is false",
			source: `
resource "boolean_something" "my-something" {
	value = "true"
}`,
			checkAttribute: "value",
			expectedResult: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := createModulesFromSource(t, test.source, ".tf")
			for _, module := range modules {
				for _, block := range module.GetBlocks() {
					attr := block.GetAttribute(test.checkAttribute)
					require.NotNil(t, attr)
					assert.Equal(t, test.expectedResult, attr.IsTrue())
				}
			}
		})
	}
}

func Test_AttributeIsFalse(t *testing.T) {
	var tests = []struct {
		name           string
		source         string
		checkAttribute string
		expectedResult bool
	}{
		{
			name: "check attribute is false",
			source: `
resource "boolean_something" "my-something" {
	value = false
}`,
			checkAttribute: "value",
			expectedResult: true,
		},
		{
			name: "check attribute as string is false",
			source: `
resource "boolean_something" "my-something" {
	value = "false"
}`,
			checkAttribute: "value",
			expectedResult: true,
		},
		{
			name: "check attribute true",
			source: `
resource "boolean_something" "my-something" {
	value = "true"
}`,
			checkAttribute: "value",
			expectedResult: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := createModulesFromSource(t, test.source, ".tf")
			for _, module := range modules {
				for _, block := range module.GetBlocks() {
					attr := block.GetAttribute(test.checkAttribute)
					require.NotNil(t, attr)
					assert.Equal(t, test.expectedResult, attr.IsFalse())
				}
			}
		})
	}
}
