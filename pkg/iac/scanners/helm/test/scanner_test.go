package test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/helm"
)

func Test_helm_scanner_with_archive(t *testing.T) {
	// TODO(simar7): Figure out why this test fails on Winndows only
	if runtime.GOOS == "windows" {
		t.Skip("skipping test on windows")
	}

	tests := []struct {
		testName    string
		chartName   string
		path        string
		archiveName string
	}{
		{
			testName:    "Parsing tarball 'mysql-8.8.26.tar'",
			chartName:   "mysql",
			path:        filepath.Join("testdata", "mysql-8.8.26.tar"),
			archiveName: "mysql-8.8.26.tar",
		},
	}

	for _, test := range tests {
		t.Logf("Running test: %s", test.testName)

		helmScanner := helm.New(rego.WithEmbeddedPolicies(true), rego.WithEmbeddedLibraries(true))

		testTemp := t.TempDir()
		testFileName := filepath.Join(testTemp, test.archiveName)
		require.NoError(t, copyArchive(test.path, testFileName))

		testFs := os.DirFS(testTemp)
		results, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
		require.NoError(t, err)
		require.NotNil(t, results)

		failed := results.GetFailed()
		assert.Len(t, failed, 13)

		visited := make(map[string]bool)
		var errorCodes []string
		for _, result := range failed {
			id := result.Flatten().RuleID
			if _, exists := visited[id]; !exists {
				visited[id] = true
				errorCodes = append(errorCodes, id)
			}
		}
		assert.Len(t, errorCodes, 13)

		sort.Strings(errorCodes)

		assert.Equal(t, []string{
			"AVD-KSV-0001", "AVD-KSV-0003",
			"AVD-KSV-0011", "AVD-KSV-0012", "AVD-KSV-0014",
			"AVD-KSV-0015", "AVD-KSV-0016", "AVD-KSV-0018",
			"AVD-KSV-0020", "AVD-KSV-0021", "AVD-KSV-0030",
			"AVD-KSV-0104", "AVD-KSV-0106",
		}, errorCodes)
	}
}

func Test_helm_scanner_with_missing_name_can_recover(t *testing.T) {

	tests := []struct {
		testName    string
		chartName   string
		path        string
		archiveName string
	}{
		{
			testName:    "Parsing tarball 'aws-cluster-autoscaler-bad.tar.gz'",
			chartName:   "aws-cluster-autoscaler",
			path:        filepath.Join("testdata", "aws-cluster-autoscaler-bad.tar.gz"),
			archiveName: "aws-cluster-autoscaler-bad.tar.gz",
		},
	}

	for _, test := range tests {
		t.Logf("Running test: %s", test.testName)

		helmScanner := helm.New(rego.WithEmbeddedPolicies(true), rego.WithEmbeddedLibraries(true))

		testTemp := t.TempDir()
		testFileName := filepath.Join(testTemp, test.archiveName)
		require.NoError(t, copyArchive(test.path, testFileName))

		testFs := os.DirFS(testTemp)
		_, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
		require.NoError(t, err)
	}
}

func Test_helm_scanner_with_dir(t *testing.T) {
	// TODO(simar7): Figure out why this test fails on Winndows only
	if runtime.GOOS == "windows" {
		t.Skip("skipping test on windows")
	}

	tests := []struct {
		testName  string
		chartName string
	}{
		{
			testName:  "Parsing directory testchart'",
			chartName: "testchart",
		},
	}

	for _, test := range tests {

		t.Logf("Running test: %s", test.testName)

		helmScanner := helm.New(rego.WithEmbeddedPolicies(true), rego.WithEmbeddedLibraries(true))

		testFs := os.DirFS(filepath.Join("testdata", test.chartName))
		results, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
		require.NoError(t, err)
		require.NotNil(t, results)

		failed := results.GetFailed()
		assert.Len(t, failed, 13)

		visited := make(map[string]bool)
		for _, result := range failed {
			visited[result.Rule().AVDID] = true
		}
		errorCodes := lo.Keys(visited)

		assert.ElementsMatch(t, []string{
			"AVD-KSV-0001", "AVD-KSV-0003",
			"AVD-KSV-0011", "AVD-KSV-0012", "AVD-KSV-0014",
			"AVD-KSV-0015", "AVD-KSV-0016",
			"AVD-KSV-0020", "AVD-KSV-0021", "AVD-KSV-0030",
			"AVD-KSV-0104", "AVD-KSV-0106",
			"AVD-KSV-0117",
		}, errorCodes)

		ignored := results.GetIgnored()
		assert.Len(t, ignored, 1)

		assert.Equal(t, "AVD-KSV-0018", ignored[0].Rule().AVDID)
		assert.Equal(t, "templates/deployment.yaml", ignored[0].Metadata().Range().GetFilename())
	}
}

func Test_helm_scanner_with_custom_policies(t *testing.T) {
	// TODO(simar7): Figure out why this test fails on Winndows only
	if runtime.GOOS == "windows" {
		t.Skip("skipping test on windows")
	}

	regoRule := `
package user.kubernetes.ID001


__rego_metadata__ := {
    "id": "ID001",
	"avd_id": "AVD-USR-ID001",
    "title": "Services not allowed",
    "severity": "LOW",
    "description": "Services are not allowed because of some reasons.",
}

__rego_input__ := {
    "selector": [
        {"type": "kubernetes"},
    ],
}

deny[res] {
    input.kind == "Service"
    msg := sprintf("Found service '%s' but services are not allowed", [input.metadata.name])
    res := result.new(msg, input)
}
`
	tests := []struct {
		testName    string
		chartName   string
		path        string
		archiveName string
	}{
		{
			testName:    "Parsing tarball 'mysql-8.8.26.tar'",
			chartName:   "mysql",
			path:        filepath.Join("testdata", "mysql-8.8.26.tar"),
			archiveName: "mysql-8.8.26.tar",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			t.Logf("Running test: %s", test.testName)

			helmScanner := helm.New(rego.WithEmbeddedPolicies(true), rego.WithEmbeddedLibraries(true),
				rego.WithPolicyDirs("rules"),
				rego.WithPolicyNamespaces("user"))

			testTemp := t.TempDir()
			testFileName := filepath.Join(testTemp, test.archiveName)
			require.NoError(t, copyArchive(test.path, testFileName))

			policyDirName := filepath.Join(testTemp, "rules")
			require.NoError(t, os.Mkdir(policyDirName, 0o700))
			require.NoError(t, os.WriteFile(filepath.Join(policyDirName, "rule.rego"), []byte(regoRule), 0o600))

			testFs := os.DirFS(testTemp)

			results, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
			require.NoError(t, err)
			require.NotNil(t, results)

			failed := results.GetFailed()
			assert.Len(t, failed, 15)

			visited := make(map[string]bool)
			for _, result := range failed {
				visited[result.Rule().AVDID] = true
			}
			errorCodes := lo.Keys(visited)

			assert.ElementsMatch(t, []string{
				"AVD-KSV-0001", "AVD-KSV-0003",
				"AVD-KSV-0011", "AVD-KSV-0012", "AVD-KSV-0014",
				"AVD-KSV-0015", "AVD-KSV-0016", "AVD-KSV-0018",
				"AVD-KSV-0020", "AVD-KSV-0021", "AVD-KSV-0030",
				"AVD-KSV-0104", "AVD-KSV-0106", "AVD-USR-ID001",
			}, errorCodes)
		})
	}
}

func copyArchive(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func Test_helm_chart_with_templated_name(t *testing.T) {
	helmScanner := helm.New(rego.WithEmbeddedPolicies(true), rego.WithEmbeddedLibraries(true))
	testFs := os.DirFS(filepath.Join("testdata", "templated-name"))
	_, err := helmScanner.ScanFS(context.TODO(), testFs, ".")
	require.NoError(t, err)
}

func TestCodeShouldNotBeMissing(t *testing.T) {
	policy := `# METADATA
# title: "Test rego"
# description: "Test rego"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: ID001
#   avd_id: AVD-USR-ID001
#   severity: LOW
#   input:
#     selector:
#     - type: kubernetes
package user.kubernetes.ID001

deny[res] {
    input.spec.replicas == 3
    res := result.new("Replicas are not allowed", input)
}
`
	helmScanner := helm.New(
		rego.WithEmbeddedPolicies(false),
		rego.WithEmbeddedLibraries(false),
		rego.WithPolicyNamespaces("user"),
		rego.WithPolicyReader(strings.NewReader(policy)),
	)

	results, err := helmScanner.ScanFS(context.TODO(), os.DirFS("testdata/simmilar-templates"), ".")
	require.NoError(t, err)

	failedResults := results.GetFailed()
	require.Len(t, failedResults, 1)

	failed := failedResults[0]
	code, err := failed.GetCode()
	require.NoError(t, err)
	assert.NotNil(t, code)
}

func TestScanSubchartOnce(t *testing.T) {
	check := `# METADATA
# title: "Test rego"
# description: "Test rego"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: ID001
#   avd_id: AVD-USR-ID001
#   severity: LOW
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: pod
package user.kubernetes.ID001

import data.lib.kubernetes

deny[res] {
	container := kubernetes.containers[_]
	container.securityContext.readOnlyRootFilesystem == false
	res := result.new("set 'securityContext.readOnlyRootFilesystem' to true", container)
}
`

	scanner := helm.New(
		rego.WithEmbeddedPolicies(false),
		rego.WithEmbeddedLibraries(true),
		rego.WithPolicyNamespaces("user"),
		rego.WithPolicyReader(strings.NewReader(check)),
	)

	results, err := scanner.ScanFS(context.TODO(), os.DirFS("testdata/with-subchart"), ".")
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Empty(t, results.GetFailed())
}
