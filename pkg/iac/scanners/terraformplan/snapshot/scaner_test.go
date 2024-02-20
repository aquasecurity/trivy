package snapshot

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func initScanner(opts ...options.ScannerOption) *Scanner {
	defaultOpts := []options.ScannerOption{
		options.ScannerWithEmbeddedPolicies(false),
		options.ScannerWithEmbeddedLibraries(true),
		options.ScannerWithPolicyNamespaces("user"),
		options.ScannerWithPolicyDirs("."),
		options.ScannerWithRegoOnly(true),
	}

	opts = append(opts, defaultOpts...)
	return New(opts...)
}

func TestScanner_Scan(t *testing.T) {

	tests := []struct {
		name        string
		dir         string
		expectedIDs []string
	}{
		{
			name:        "one resource",
			dir:         "just-resource",
			expectedIDs: []string{"ID001"},
		},
		{
			name:        "with local module",
			dir:         "with-local-module",
			expectedIDs: []string{"ID001"},
		},
		{
			name:        "with remote module",
			dir:         "with-remote-module",
			expectedIDs: []string{"ID001"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", tt.dir, "tfplan"))
			require.NoError(t, err)
			defer f.Close()

			policyFS := os.DirFS(filepath.Join("testdata", tt.dir, "checks"))

			s := initScanner(options.ScannerWithPolicyFilesystem(policyFS))
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
