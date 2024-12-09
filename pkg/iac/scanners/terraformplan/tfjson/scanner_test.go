package tfjson

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

const defaultCheck = `package defsec.abcdefg

__rego_metadata__ := {
	"id": "TEST123",
	"avd_id": "AVD-TEST-0123",
	"title": "Buckets should not be evil",
	"short_code": "no-evil-buckets",
	"severity": "CRITICAL",
	"type": "DefSec Security Check",
	"description": "You should not allow buckets to be evil",
	"recommended_actions": "Use a good bucket instead",
	"url": "https://google.com/search?q=is+my+bucket+evil",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "cloud", "subtypes": [{"service": "s3", "provider": "aws"}]}],
}

deny[cause] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "tfsec-plan-testing"
	cause := bucket.name
}`

func Test_TerraformScanner(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		inputFile string
		check     string
		options   []options.ScannerOption
	}{
		{
			name:      "old rego metadata",
			inputFile: "test/testdata/plan.json",
			check:     defaultCheck,
			options: []options.ScannerOption{
				rego.WithPolicyDirs("rules"),
			},
		},
		{
			name:      "with user namespace",
			inputFile: "test/testdata/plan.json",
			check:     defaultCheck,
			options: []options.ScannerOption{
				rego.WithPolicyDirs("rules"),
				rego.WithPolicyNamespaces("user"),
			},
		},
		{
			name:      "with templated plan json",
			inputFile: "test/testdata/plan_with_template.json",
			check: `
# METADATA
# title: Bad buckets are bad
# description: Bad buckets are bad because they are not good.
# scope: package
# schemas:
#   - input: schema["input"]
# custom:
#   avd_id: AVD-TEST-0123
#   severity: CRITICAL
#   short_code: very-bad-misconfig
#   recommended_action: "Fix the s3 bucket"

package user.foobar.ABC001

deny[cause] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "${template-name-is-$evil}"
	cause := bucket.name
}
`,
			options: []options.ScannerOption{
				rego.WithPolicyDirs("rules"),
				rego.WithPolicyNamespaces("user"),
			},
		},
		{
			name:      "plan with arbitrary name",
			inputFile: "test/testdata/arbitrary_name.json",
			check:     defaultCheck,
			options: []options.ScannerOption{
				rego.WithPolicyDirs("rules"),
				rego.WithPolicyNamespaces("user"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := os.ReadFile(tc.inputFile)
			fs := testutil.CreateFS(t, map[string]string{
				"/code/main.tfplan.json": string(b),
				"/rules/test.rego":       tc.check,
			})

			so := append(tc.options, rego.WithPolicyFilesystem(fs))
			scanner := New(so...)

			results, err := scanner.ScanFS(context.TODO(), fs, "code")
			require.NoError(t, err)

			require.Len(t, results.GetFailed(), 1)

			failure := results.GetFailed()[0]

			assert.Equal(t, "AVD-TEST-0123", failure.Rule().AVDID)
		})
	}
}
