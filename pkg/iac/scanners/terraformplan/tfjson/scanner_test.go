package tfjson_test

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraformplan/tfjson"
)

const defaultCheck = `package defsec.abcdefg

__rego_metadata__ := {
	"id": "TEST-0123",
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

func TestScanner_ScanFS(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		input    string
		options  []options.ScannerOption
		expected []string
	}{
		{
			name:  "use builtin checks",
			input: "testdata/plan.json",
			options: []options.ScannerOption{
				rego.WithEmbeddedPolicies(true),
				rego.WithEmbeddedLibraries(true),
			},
			expected: []string{
				"AWS-0093",
				"AWS-0086",
				"AWS-0132",
				"AWS-0094",
				"AWS-0087",
				"AWS-0091",
				"AWS-0099",
				"AWS-0124",
			},
		},
		{
			name:  "with user namespace",
			input: "testdata/plan.json",
			options: []options.ScannerOption{
				rego.WithPolicyReader(strings.NewReader(defaultCheck)),
				rego.WithPolicyNamespaces("user"),
			},
			expected: []string{"TEST-0123"},
		},
		{
			name:  "with templated plan json",
			input: "testdata/plan_with_template.json",
			options: []options.ScannerOption{
				rego.WithPolicyReader(strings.NewReader(`# METADATA
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: TEST-0123
package user.foobar.ABC001

deny[cause] {
	bucket := input.aws.s3.buckets[_]
	bucket.name.value == "${template-name-is-$evil}"
	cause := bucket.name
}`)),
				rego.WithPolicyNamespaces("user"),
			},
			expected: []string{"TEST-0123"},
		},
		{
			name:  "plan with arbitrary name",
			input: "testdata/arbitrary_name.json",
			options: []options.ScannerOption{
				rego.WithPolicyReader(strings.NewReader(defaultCheck)),
				rego.WithPolicyNamespaces("user"),
			},
			expected: []string{"TEST-0123"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := os.ReadFile(tc.input)
			require.NoError(t, err)

			fsys := fstest.MapFS{
				"main.tfplan.json": {Data: b},
			}

			scanner := tfjson.New(tc.options...)
			results, err := scanner.ScanFS(t.Context(), fsys, ".")
			require.NoError(t, err)

			var got []string
			for _, r := range results.GetFailed() {
				got = append(got, r.Rule().ID)
			}

			assert.ElementsMatch(t, tc.expected, got)
		})
	}
}
