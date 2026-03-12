package report_test

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/hooktest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestResults_Failed(t *testing.T) {
	tests := []struct {
		name    string
		results types.Results
		want    bool
	}{
		{
			name: "no vulnerabilities and misconfigurations",
			results: types.Results{
				{
					Target: "test",
					Type:   "test",
				},
			},
			want: false,
		},
		{
			name: "vulnerabilities found",
			results: types.Results{
				{
					Target: "test",
					Type:   "test",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID: "CVE-2021-0001",
							PkgName:         "test",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "failed misconfigurations",
			results: types.Results{
				{
					Target: "test",
					Type:   "test",
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Type:   "Docker Security Check",
							ID:     "ID-001",
							Status: types.MisconfStatusFailure,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "passed misconfigurations",
			results: types.Results{
				{
					Target: "test",
					Type:   "test",
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Type:   "Docker Security Check",
							ID:     "ID-001",
							Status: types.MisconfStatusPassed,
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.results.Failed()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestWrite(t *testing.T) {
	testReport := types.Report{
		SchemaVersion: report.SchemaVersion,
		ArtifactName:  "test-artifact",
		Results: types.Results{
			{
				Target: "test-target",
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID: "CVE-2021-0001",
						PkgName:         "test-pkg",
						Vulnerability: dbTypes.Vulnerability{
							Title:       "Test Vulnerability Title",
							Description: "This is a test description of a vulnerability",
						},
					},
				},
			},
		},
	}
	testTemplate := "{{ range . }}{{ range .Vulnerabilities }}- {{ .VulnerabilityID }}: {{ .Title }}\n  {{ .Description }}\n{{ end }}{{ end }}"

	tests := []struct {
		name       string
		setUpHook  bool
		report     types.Report
		options    flag.Options
		wantOutput string
		wantTitle  string // Expected title after function call
		wantDesc   string // Expected description after function call
	}{
		{
			name:   "template with title and description",
			report: testReport,
			options: flag.Options{
				ReportOptions: flag.ReportOptions{
					Format:   types.FormatTemplate,
					Template: testTemplate,
				},
			},
			wantOutput: "- CVE-2021-0001: Test Vulnerability Title\n  This is a test description of a vulnerability\n",
			wantTitle:  "Test Vulnerability Title",                      // Should remain unchanged
			wantDesc:   "This is a test description of a vulnerability", // Should remain unchanged
		},
		{
			name:      "report modified by hooks",
			setUpHook: true,
			report:    testReport,
			options: flag.Options{
				ReportOptions: flag.ReportOptions{
					Format:   types.FormatTemplate,
					Template: testTemplate,
				},
			},
			// The template output only reflects the pre-report hook changes because
			// the post-report hook runs AFTER the output is written.
			// However, the report object itself is modified by both pre and post hooks.
			wantOutput: "- CVE-2021-0001: Modified by pre-report hook\n  This is a test description of a vulnerability\n",
			wantTitle:  "Modified by pre-report hook",
			wantDesc:   "Modified by post-report hook",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setUpHook {
				hooktest.Init(t)
			}

			// Create a buffer to capture the output
			output := new(bytes.Buffer)
			tt.options.SetOutputWriter(output)

			// Execute the Write function
			err := report.Write(t.Context(), tt.report, tt.options)
			require.NoError(t, err)

			// Verify the output matches the expected template rendering
			got := output.String()
			assert.Equal(t, tt.wantOutput, got, "Template output does not match wanted value")

			// Verify that the title and description in the report match the expected values
			require.Len(t, tt.report.Results, 1)
			require.Len(t, tt.report.Results[0].Vulnerabilities, 1)
			assert.Equal(t, tt.wantTitle, tt.report.Results[0].Vulnerabilities[0].Title)
			assert.Equal(t, tt.wantDesc, tt.report.Results[0].Vulnerabilities[0].Description)
		})
	}
}

func TestWrite_Sarif(t *testing.T) {
	// On Unix: file:///tmp/foo/, on Windows: file:///D:/tmp/foo/
	tmpFooRootPath := regexp.MustCompile(`^file:///([A-Z]:/)?tmp/foo/$`)

	tests := []struct {
		name         string
		artifactType ftypes.ArtifactType
		target       string
		wantRootPath *regexp.Regexp
	}{
		{
			name:         "TypeFilesystem sets ROOTPATH to target path",
			artifactType: ftypes.TypeFilesystem,
			target:       "/tmp/foo",
			wantRootPath: tmpFooRootPath,
		},
		{
			name:         "TypeRepository sets ROOTPATH to target path",
			artifactType: ftypes.TypeRepository,
			target:       "/tmp/foo",
			wantRootPath: tmpFooRootPath,
		},
		{
			name:         "TypeContainerImage does not set ROOTPATH",
			artifactType: ftypes.TypeContainerImage,
			target:       "/tmp/foo",
			wantRootPath: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := new(bytes.Buffer)
			opts := flag.Options{
				ScanOptions: flag.ScanOptions{
					Target: tt.target,
				},
				ReportOptions: flag.ReportOptions{
					Format: types.FormatSarif,
				},
			}
			opts.SetOutputWriter(output)

			err := report.Write(t.Context(), types.Report{ArtifactType: tt.artifactType}, opts)
			require.NoError(t, err)

			var result struct {
				Runs []struct {
					OriginalUriBaseIDs map[string]struct {
						URI string `json:"uri"`
					} `json:"originalUriBaseIds"`
				} `json:"runs"`
			}
			err = json.Unmarshal(output.Bytes(), &result)
			require.NoError(t, err)
			require.Len(t, result.Runs, 1)

			if tt.wantRootPath != nil {
				assert.Regexp(t, tt.wantRootPath, result.Runs[0].OriginalUriBaseIDs["ROOTPATH"].URI)
			} else {
				assert.Empty(t, result.Runs[0].OriginalUriBaseIDs["ROOTPATH"].URI)
			}
		})
	}
}
