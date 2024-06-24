package tfjson

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

func Test_TerraformScanner(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		inputFile string
		inputRego string
		options   []options.ScannerOption
	}{
		{
			name:      "old rego metadata",
			inputFile: "test/testdata/plan.json",
			inputRego: `
package defsec.abcdefg

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
}
`,
			options: []options.ScannerOption{
				options.ScannerWithPolicyDirs("rules"),
				options.ScannerWithRegoOnly(true),
				options.ScannerWithEmbeddedPolicies(false)},
		},
		{
			name:      "with user namespace",
			inputFile: "test/testdata/plan.json",
			inputRego: ` 
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
	bucket.name.value == "tfsec-plan-testing"
	cause := bucket.name
}
`,
			options: []options.ScannerOption{
				options.ScannerWithPolicyDirs("rules"),
				options.ScannerWithRegoOnly(true),
				options.ScannerWithEmbeddedPolicies(false),
				options.ScannerWithPolicyNamespaces("user"),
			},
		},
		{
			name:      "with templated plan json",
			inputFile: "test/testdata/plan_with_template.json",
			inputRego: `
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
				options.ScannerWithPolicyDirs("rules"),
				options.ScannerWithRegoOnly(true),
				options.ScannerWithEmbeddedPolicies(false),
				options.ScannerWithPolicyNamespaces("user"),
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			b, _ := os.ReadFile(tc.inputFile)
			fs := testutil.CreateFS(t, map[string]string{
				"/code/main.tfplan.json": string(b),
				"/rules/test.rego":       tc.inputRego,
			})

			debugLog := bytes.NewBuffer([]byte{})
			so := append(tc.options, options.ScannerWithDebug(debugLog), options.ScannerWithPolicyFilesystem(fs))
			scanner := New(so...)

			results, err := scanner.ScanFS(context.TODO(), fs, "code")
			require.NoError(t, err)

			require.Len(t, results.GetFailed(), 1)

			failure := results.GetFailed()[0]

			assert.Equal(t, "AVD-TEST-0123", failure.Rule().AVDID)
			if t.Failed() {
				fmt.Printf("Debug logs:\n%s\n", debugLog.String())
			}
		})
	}
}
