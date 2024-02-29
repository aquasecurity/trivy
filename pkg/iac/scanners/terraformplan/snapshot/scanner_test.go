package snapshot

import (
	"bytes"
	"context"
	"os"
	"path"
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

func Test_ScanFS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		dir         string
		expectedDir string
	}{
		{
			dir:         "just-resource",
			expectedDir: "main.tf",
		},
		{
			dir:         "with-local-module",
			expectedDir: path.Join("modules", "ec2", "main.tf"),
		},
		{
			dir:         "with-remote-module",
			expectedDir: path.Join("terraform-aws-modules", "s3-bucket", "aws", "main.tf"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.dir, func(t *testing.T) {
			fs := os.DirFS("testdata")

			debugLog := bytes.NewBuffer([]byte{})
			scanner := New(
				options.ScannerWithDebug(debugLog),
				options.ScannerWithPolicyDirs(path.Join(tc.dir, "checks")),
				options.ScannerWithPolicyFilesystem(fs),
				options.ScannerWithRegoOnly(true),
				options.ScannerWithPolicyNamespaces("user"),
				options.ScannerWithEmbeddedLibraries(false),
				options.ScannerWithEmbeddedPolicies(false),
				options.ScannerWithRegoErrorLimits(0),
			)

			results, err := scanner.ScanFS(context.TODO(), fs, path.Join(tc.dir, "tfplan"))
			require.NoError(t, err)
			require.Len(t, results, 1)

			failed := results.GetFailed()
			assert.Len(t, failed, 1)

			occurrences := failed[0].Occurrences()
			assert.Equal(t, tc.expectedDir, occurrences[0].Filename, tc.dir)
		})
	}

}
