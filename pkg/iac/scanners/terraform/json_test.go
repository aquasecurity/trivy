package terraform

import (
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
)

func TestScanningJSON(t *testing.T) {

	var tests = []struct {
		name     string
		source   string
		expected bool
	}{
		{
			name: "check results are picked up in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"aws_s3_bucket": {
						"test": {
							"bucket": ""
						}
					}
				}
			}`,
			expected: true,
		},
		{
			name: "check attributes are checked in tf json configs",
			source: `
			{
				"provider": {
					"aws": {
						"profile": null,
						"region": "eu-west-1"
					}
				},
				"resource": {
					"aws_s3_bucket": {
						"test": {
							"bucket": "test"
						}
					}
				}
			}`,
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanJSON(t, test.source,
				rego.WithPolicyReader(strings.NewReader(emptyBucketCheck)),
				rego.WithPolicyNamespaces("user"),
			)
			if test.expected {
				testutil.AssertRuleFound(t, "aws-s3-non-empty-bucket", results, "false negative found")
			} else {
				testutil.AssertRuleNotFound(t, "aws-s3-non-empty-bucket", results, "false positive found")
			}
		})
	}
}
