package test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/trivy/pkg/scanners/dockerfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// func addFilesToMemFS(memfs *memoryfs.FS, typePolicy bool, folderName string) error {
//	base := filepath.Base(folderName)
//	if err := memfs.MkdirAll(base, 0o700); err != nil {
//		return err
//	}
//	err := filepath.Walk(filepath.FromSlash(folderName),
//		func(fpath string, info os.FileInfo, err error) error {
//			if err != nil {
//				return err
//			}
//			if info.IsDir() {
//				return nil
//			}
//			if typePolicy && !rego.IsRegoFile(info.Name()) {
//				return nil
//			}
//			data, err := os.ReadFile(fpath)
//			if err != nil {
//				return err
//			}
//			fileName := getFileName(fpath, info, typePolicy)
//			if err := memfs.WriteFile(path.Join(base, fileName), data, 0o644); err != nil {
//				return err
//			}
//			return nil
//		})
//
//	if err != nil {
//		return err
//	}
//	return nil
//}

// TODO: Evaluate usefulness of this test
// func Test_Docker_RegoPoliciesFromDisk(t *testing.T) {
//	t.Parallel()
//
//	entries, err := os.ReadDir("./testdata/dockerfile")
//	require.NoError(t, err)
//
//	policiesPath, err := filepath.Abs("../rules")
//	require.NoError(t, err)
//	scanner := dockerfile.NewScanner(
//		options.ScannerWithPolicyDirs(filepath.Base(policiesPath)),
//	)
//	memfs := memoryfs.New()
//	// add policies
//	err = addFilesToMemFS(memfs, true, policiesPath)
//	require.NoError(t, err)
//
//	// add test data
//	testDataPath, err := filepath.Abs("./testdata/dockerfile")
//	require.NoError(t, err)
//	err = addFilesToMemFS(memfs, false, testDataPath)
//	require.NoError(t, err)
//
//	results, err := scanner.ScanFS(context.TODO(), memfs, filepath.Base(testDataPath))
//	require.NoError(t, err)
//
//	for _, entry := range entries {
//		if !entry.IsDir() {
//			continue
//		}
//		t.Run(entry.Name(), func(t *testing.T) {
//			require.NoError(t, err)
//			t.Run(entry.Name(), func(t *testing.T) {
//				var matched int
//				for _, result := range results {
//					if result.Rule().HasID(entry.Name()) && result.Status() == scan.StatusFailed {
//						if result.Description() != "Specify at least 1 USER command in Dockerfile with non-root user as argument" {
//							assert.Greater(t, result.Range().GetStartLine(), 0)
//							assert.Greater(t, result.Range().GetEndLine(), 0)
//						}
//						if !strings.HasSuffix(result.Range().GetFilename(), entry.Name()) {
//							continue
//						}
//						matched++
//					}
//				}
//				assert.Equal(t, 1, matched, "Rule should be matched once")
//			})
//
//		})
//	}
//}

func Test_Docker_RegoPoliciesEmbedded(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("./testdata/dockerfile")
	require.NoError(t, err)

	scanner := dockerfile.NewScanner(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true))
	srcFS := os.DirFS("../")

	results, err := scanner.ScanFS(context.TODO(), srcFS, "test/testdata/dockerfile")
	require.NoError(t, err)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			require.NoError(t, err)
			t.Run(entry.Name(), func(t *testing.T) {
				var matched bool
				for _, result := range results {
					if result.Rule().HasID(entry.Name()) && result.Status() == scan.StatusFailed {
						if result.Description() != "Specify at least 1 USER command in Dockerfile with non-root user as argument" {
							assert.Greater(t, result.Range().GetStartLine(), 0)
							assert.Greater(t, result.Range().GetEndLine(), 0)
						}
						assert.Equal(t, fmt.Sprintf("test/testdata/dockerfile/%s/Dockerfile.denied", entry.Name()), result.Range().GetFilename())
						matched = true
					}
				}
				assert.True(t, matched)
			})

		})
	}
}
