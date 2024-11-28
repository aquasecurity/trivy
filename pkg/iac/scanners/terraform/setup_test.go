package terraform

import (
	"context"
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform/parser"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

var emptyBucketCheck = `# METADATA
# schemas:
# - input: schema.cloud
# custom:
#   avd_id: USER-TEST-0123
#   short_code: non-empty-bucket
#   provider: aws
#   service: s3
#   aliases:
#   - my-alias
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: s3
#           provider: aws
package user.test123

import rego.v1

deny contains res if  {
	some bucket in input.aws.s3.buckets
	bucket.name.value == ""
	res := result.new("The bucket name cannot be empty.", bucket.name)
}
`

var enforceGroupMfaCheck = `# METADATA
# schemas:
#   - input: schema["cloud"]
# custom:
#   id: USER-TEST-0124
#   aliases:
#     - aws-iam-enforce-mfa
#   provider: aws
#   service: iam
#   short_code: enforce-group-mfa
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package user.test124

import rego.v1

deny contains res if {
	some group in input.aws.iam.groups
	not is_group_mfa_enforced(group)
	res := result.new("Multi-Factor authentication is not enforced for group", group)
}

is_group_mfa_enforced(group) if {
	some policy in group.policies
	value := json.unmarshal(policy.document.value)
	some condition in value.Statement[_].Condition
	some key, _ in condition
	key == "aws:MultiFactorAuthPresent"
}
`

func createModulesFromSource(t *testing.T, source, ext string) terraform.Modules {
	fs := testutil.CreateFS(t, map[string]string{
		"source" + ext: source,
	})

	p := parser.New(fs, "", parser.OptionStopOnHCLError(true))
	if err := p.ParseFS(context.TODO(), "."); err != nil {
		t.Fatal(err)
	}
	modules, _, err := p.EvaluateAll(context.TODO())
	if err != nil {
		t.Fatalf("parse error: %s", err)
	}
	return modules
}

func scanFS(fsys fs.FS, target string, opts ...options.ScannerOption) (scan.Results, error) {
	s := New(append(
		[]options.ScannerOption{
			rego.WithEmbeddedLibraries(true),
			rego.WithRegoErrorLimits(0),
			ScannerWithAllDirectories(true),
			ScannerWithSkipCachedModules(true),
			ScannerWithStopOnHCLError(true),
		},
		opts...,
	)...,
	)

	return s.ScanFS(context.TODO(), fsys, target)
}

func scanHCL(t *testing.T, source string, opts ...options.ScannerOption) scan.Results {

	fsys := testutil.CreateFS(t, map[string]string{
		"main.tf": source,
	})
	results, err := scanFS(fsys, ".", opts...)
	require.NoError(t, err)
	return results
}

func scanJSON(t *testing.T, source string, opts ...options.ScannerOption) scan.Results {

	fsys := testutil.CreateFS(t, map[string]string{
		"main.tf.json": source,
	})

	results, err := scanFS(fsys, ".", opts...)
	require.NoError(t, err)
	return results
}
