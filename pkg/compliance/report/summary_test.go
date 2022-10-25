package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestBuildSummary(t *testing.T) {
	tests := []struct {
		name                  string
		specPath              string
		resultPath            string
		wantSummaryReportPath string
	}{
		{name: "build report summary config only", specPath: "./testdata/config_spec.yaml", resultPath: "./testdata/results_config.json", wantSummaryReportPath: "./testdata/report_summary.json"},
		{name: "build report summary config and vuln", specPath: "./testdata/config_vuln_spec.yaml", resultPath: "./testdata/results_vul_config.json", wantSummaryReportPath: "./testdata/vuln_config_summary.json"}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specfile, err := os.ReadFile(tt.specPath)
			assert.NoError(t, err)
			var res types.Results
			c, err := os.ReadFile(tt.resultPath)
			err = json.Unmarshal(c, &res)
			assert.NoError(t, err)
			complianceResults, err := BuildComplianceReport([]types.Results{res}, string(specfile))
			tk := BuildSummary(complianceResults)
			o, err := json.Marshal(tk)
			assert.NoError(t, err)
			r, err := os.ReadFile(tt.wantSummaryReportPath)
			assert.NoError(t, err)
			assert.Equal(t, strings.TrimSpace(string(o)), string(r))

		})
	}
}

func TestCalculatePercentage(t *testing.T) {
	tests := []struct {
		name string
		pass float32
		fail float32
		want string
	}{
		{name: "calcuale percentage pass bigger then fail", pass: 10.0, fail: 5.0, want: "66.67%"},
		{name: "calcuale percentage pass smaller then fail", pass: 5.0, fail: 10.0, want: "33.33%"},
		{name: "calcuale percentage pass zero and fail zero", pass: 0.0, fail: 0.0, want: "0.00%"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calculatePercentage(tt.fail, tt.pass)
			assert.Equal(t, got, tt.want)

		})
	}
}
