package snapshot

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"sort"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	tfscanner "github.com/aquasecurity/trivy/pkg/iac/scanners/terraform"
)

func initScanner(opts ...options.ScannerOption) *Scanner {
	defaultOpts := []options.ScannerOption{
		rego.WithEmbeddedPolicies(false),
		rego.WithEmbeddedLibraries(true),
		rego.WithPolicyNamespaces("user"),
		rego.WithPolicyDirs("."),
		rego.WithRegoErrorLimits(0),
		tfscanner.ScannerWithSkipCachedModules(true),
	}

	opts = append(opts, defaultOpts...)
	return New(opts...)
}

func TestScanner_Scan(t *testing.T) {
	tests := []struct {
		dir         string
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
	}

	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", tt.dir, "tfplan"))
			require.NoError(t, err)
			defer f.Close()

			policyFS := os.DirFS(filepath.Join("testdata", tt.dir, "checks"))

			s := initScanner(rego.WithPolicyFilesystem(policyFS))
			result, err := s.Scan(context.TODO(), f)
			require.NoError(t, err)

			failed := result.GetFailed()

			assert.Len(t, failed, len(tt.expectedIDs))

			ids := lo.Map(failed, func(res scan.Result, _ int) string {
				return res.Rule().AVDID
			})
			sort.Strings(ids)

			assert.Equal(t, tt.expectedIDs, ids)
		})
	}
}

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

			results, err := scanner.ScanFS(context.TODO(), fs, path.Join(tc.dir, "tfplan"))
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
