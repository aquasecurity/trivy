package parser_test

import (
	"bytes"
	"io/fs"
	"os"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraformplan/tfjson/parser"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name: "simple case",
			path: "../testdata/plan.json",
			expected: `resource "aws_s3_bucket" "planbucket" {
  bucket = "tfsec-plan-testing"
  force_destroy = false
  logging {
    target_bucket = "arn:aws:s3:::iac-tfsec-dev"
  }
  versioning {
    enabled = true
    mfa_delete = false
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.planbucket.id
  rule {
    bucket_key_enabled = true
    apply_server_side_encryption_by_default {
      kms_master_key_id = ""
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_security_group" "sg" {
  description = "Managed by Terraform"
  name = "sg"
  revoke_rules_on_delete = false
  tags = {
    "Name" = "blah"
  }
  tags_all = {
    "Name" = "blah"
  }
  ingress {
    cidr_blocks = [
      "0.0.0.0/0",
    ]
    description = ""
    from_port = 80
    ipv6_cidr_blocks = []
    prefix_list_ids = []
    protocol = "tcp"
    security_groups = []
    self = false
    to_port = 80
  }
}
`,
		},
		{
			name: "with module call",
			path: "../testdata/module_call.json",
			expected: `resource "aws_s3_bucket" "main_c3bbddd8ef830639c0419b6b59b1fd80" {
  bucket = "test"
  force_destroy = false
  region = "eu-west-1"
}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			require.NoError(t, err)

			planFile, err := parser.New().Parse(bytes.NewReader(data))
			require.NoError(t, err)
			assert.NotNil(t, planFile)

			fsys, err := planFile.ToFS()
			require.NoError(t, err)
			assert.NotNil(t, fsys)

			b, err := fs.ReadFile(fsys, parser.TerraformMainFile)
			require.NoError(t, err)

			assert.Equal(t, tt.expected, string(b))

			_, diags := hclparse.NewParser().ParseHCL(b, "main.tf")
			if diags.HasErrors() {
				assert.NoError(t, diags)
			}
		})
	}
}
