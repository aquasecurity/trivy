package terraform

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

var emptyBucketCheck = `# METADATA
# schemas:
# - input: schema.cloud
# custom:
#   id: USER-TEST-0123
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

func scanFS(t *testing.T, fsys fs.FS, target string, opts ...options.ScannerOption) scan.Results {
	t.Helper()

	defaultOpts := []options.ScannerOption{
		rego.WithEmbeddedLibraries(true),
		rego.WithEmbeddedPolicies(false),
		rego.WithMaxAllowedErrors(0),
		ScannerWithAllDirectories(true),
		ScannerWithSkipCachedModules(true),
		ScannerWithStopOnHCLError(true),
	}

	s := New(append(defaultOpts, opts...)...)

	results, err := s.ScanFS(t.Context(), fsys, target)
	require.NoError(t, err)
	return results
}

func scanHCL(t *testing.T, source string, opts ...options.ScannerOption) scan.Results {
	t.Helper()

	fsys := testutil.CreateFS(map[string]string{
		"main.tf": source,
	})
	return scanFS(t, fsys, ".", opts...)
}

func scanJSON(t *testing.T, source string, opts ...options.ScannerOption) scan.Results {
	t.Helper()

	fsys := testutil.CreateFS(map[string]string{
		"main.tf.json": source,
	})

	return scanFS(t, fsys, ".", opts...)
}
