package test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/helm/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

func Test_helm_parser_with_options_with_values_file(t *testing.T) {

	tests := []struct {
		testName   string
		chartName  string
		valuesFile string
	}{
		{
			testName:   "Parsing directory 'testchart'",
			chartName:  "testchart",
			valuesFile: "values/values.yaml",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			chartName := test.chartName

			t.Logf("Running test: %s", test.testName)

			var opts []options.ParserOption

			if test.valuesFile != "" {
				opts = append(opts, parser2.OptionWithValuesFile(test.valuesFile))
			}

			helmParser := parser2.New(chartName, opts...)
			err := helmParser.ParseFS(context.TODO(), os.DirFS(filepath.Join("testdata", chartName)), ".")
			require.NoError(t, err)
			manifests, err := helmParser.RenderedChartFiles()
			require.NoError(t, err)

			assert.Len(t, manifests, 3)

			for _, manifest := range manifests {
				expectedPath := filepath.Join("testdata", "expected", "options", chartName, manifest.TemplateFilePath)

				expectedContent, err := os.ReadFile(expectedPath)
				require.NoError(t, err)

				cleanExpected := strings.ReplaceAll(string(expectedContent), "\r\n", "\n")
				cleanActual := strings.ReplaceAll(manifest.ManifestContent, "\r\n", "\n")

				assert.Equal(t, cleanExpected, cleanActual)
			}
		})
	}
}

func Test_helm_parser_with_options_with_set_value(t *testing.T) {

	tests := []struct {
		testName   string
		chartName  string
		valuesFile string
		values     string
	}{
		{
			testName:  "Parsing directory 'testchart'",
			chartName: "testchart",
			values:    "securityContext.runAsUser=0",
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			chartName := test.chartName

			t.Logf("Running test: %s", test.testName)

			var opts []options.ParserOption

			if test.valuesFile != "" {
				opts = append(opts, parser2.OptionWithValuesFile(test.valuesFile))
			}

			if test.values != "" {
				opts = append(opts, parser2.OptionWithValues(test.values))
			}

			helmParser := parser2.New(chartName, opts...)
			err := helmParser.ParseFS(context.TODO(), os.DirFS(filepath.Join("testdata", chartName)), ".")
			require.NoError(t, err)
			manifests, err := helmParser.RenderedChartFiles()
			require.NoError(t, err)

			assert.Len(t, manifests, 3)

			for _, manifest := range manifests {
				expectedPath := filepath.Join("testdata", "expected", "options", chartName, manifest.TemplateFilePath)

				expectedContent, err := os.ReadFile(expectedPath)
				require.NoError(t, err)

				cleanExpected := strings.ReplaceAll(string(expectedContent), "\r\n", "\n")
				cleanActual := strings.ReplaceAll(manifest.ManifestContent, "\r\n", "\n")

				assert.Equal(t, cleanExpected, cleanActual)
			}
		})
	}
}

func Test_helm_parser_with_options_with_api_versions(t *testing.T) {

	tests := []struct {
		testName    string
		chartName   string
		apiVersions []string
	}{
		{
			testName:    "Parsing directory 'with-api-version'",
			chartName:   "with-api-version",
			apiVersions: []string{"policy/v1/PodDisruptionBudget"},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			chartName := test.chartName

			t.Logf("Running test: %s", test.testName)

			var opts []options.ParserOption

			if len(test.apiVersions) > 0 {
				opts = append(opts, parser2.OptionWithAPIVersions(test.apiVersions...))
			}

			helmParser := parser2.New(chartName, opts...)
			err := helmParser.ParseFS(context.TODO(), os.DirFS(filepath.Join("testdata", chartName)), ".")
			require.NoError(t, err)
			manifests, err := helmParser.RenderedChartFiles()
			require.NoError(t, err)

			assert.Len(t, manifests, 1)

			for _, manifest := range manifests {
				expectedPath := filepath.Join("testdata", "expected", "options", chartName, manifest.TemplateFilePath)

				expectedContent, err := os.ReadFile(expectedPath)
				require.NoError(t, err)

				cleanExpected := strings.TrimSpace(strings.ReplaceAll(string(expectedContent), "\r\n", "\n"))
				cleanActual := strings.TrimSpace(strings.ReplaceAll(manifest.ManifestContent, "\r\n", "\n"))

				assert.Equal(t, cleanExpected, cleanActual)
			}
		})
	}
}
