package snapshot

import (
	"os"
	"path"
	"sort"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	tfscanner "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform"
)

func Test_ScanFS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		dir         string
		expectedDir string
		expectedIDs []string
	}{
		{
			dir:         "just-resource",
			expectedIDs: []string{"ID001"},
		},
		{
			dir:         "with-local-module",
			expectedIDs: []string{"ID001"},
		},
		{
			dir:         "with-remote-module",
			expectedIDs: []string{"ID001"},
		},
		{
			dir:         "with-var",
			expectedIDs: []string{"ID001"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.dir, func(t *testing.T) {
			fs := os.DirFS("testdata")

			scanner := New(
				rego.WithPolicyDirs(path.Join(tc.dir, "checks")),
				rego.WithPolicyFilesystem(fs),
				rego.WithPolicyNamespaces("user"),
				rego.WithEmbeddedLibraries(false),
				rego.WithEmbeddedPolicies(false),
				rego.WithRegoErrorLimits(0),
				tfscanner.ScannerWithSkipCachedModules(true),
			)

			results, err := scanner.ScanFS(t.Context(), fs, path.Join(tc.dir, "tfplan"))
			require.NoError(t, err)
			require.Len(t, results, 1)

			failed := results.GetFailed()

			assert.Len(t, failed, len(tc.expectedIDs))

			ids := lo.Map(failed, func(res scan.Result, _ int) string {
				return res.Rule().AVDID
			})
			sort.Strings(ids)

			assert.Equal(t, tc.expectedIDs, ids)
		})
	}
}
