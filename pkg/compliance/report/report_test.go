package report

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestReport(t *testing.T) {
	tests := []struct {
		name                  string
		specPath              string
		resultPath            string
		Option                Option
		wantSummaryReportPath string
		expectError           bool
	}{
		{name: "build table report summary", Option: Option{Report: "summary", Format: "table"}, specPath: "./testdata/config_spec.yaml", resultPath: "./testdata/results_config.json", wantSummaryReportPath: "./testdata/table_summary.txt"},
		{name: "build table report", Option: Option{Report: "all", Format: "table"}, specPath: "./testdata/config_spec.yaml", resultPath: "./testdata/results_config.json", wantSummaryReportPath: "./testdata/table.txt"},
		{name: "build json report summary", Option: Option{Report: "summary", Format: "json"}, specPath: "./testdata/config_spec.yaml", resultPath: "./testdata/results_config.json", wantSummaryReportPath: "./testdata/json_summary.json"},
		{name: "build json report", Option: Option{Report: "all", Format: "json"}, specPath: "./testdata/config_spec.yaml", resultPath: "./testdata/results_config.json", wantSummaryReportPath: "./testdata/json_view.json"},
		{name: "build report bad format", Option: Option{Report: "all", Format: "aaa"}, specPath: "./testdata/config_spec.yaml", resultPath: "./testdata/results_config.json", wantSummaryReportPath: "./testdata/json_view.json", expectError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specfile, err := os.ReadFile(tt.specPath)
			assert.NoError(t, err)
			var res types.Results
			resultByte, err := os.ReadFile(tt.resultPath)
			err = json.Unmarshal(resultByte, &res)
			assert.NoError(t, err)
			complianceResults, err := BuildComplianceReport([]types.Results{res}, string(specfile))
			ioWriter := new(bytes.Buffer)
			tt.Option.Output = ioWriter
			err = Write(complianceResults, tt.Option, false)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				bt, err := io.ReadAll(ioWriter)
				assert.NoError(t, err)
				r, err := os.ReadFile(tt.wantSummaryReportPath)
				assert.NoError(t, err)
				assert.Equal(t, string(bt), string(r))
			}
		})
	}
}

func TestBuildComplianceReportResults(t *testing.T) {
	tests := []struct {
		name                 string
		specPath             string
		resultPath           string
		complianceReportPath string
	}{
		{name: "build report test config and vuln", specPath: "./testdata/config_vuln_spec.yaml", resultPath: "./testdata/results_vul_config.json", complianceReportPath: "./testdata/vuln_config_compliance.json"}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specFile, err := os.ReadFile(tt.specPath)
			assert.NoError(t, err)
			var res types.Results
			c, err := os.ReadFile(tt.resultPath)
			err = json.Unmarshal(c, &res)
			assert.NoError(t, err)
			pp, err := BuildComplianceReport([]types.Results{res}, string(specFile))
			assert.NoError(t, err)
			complianceReport, err := os.ReadFile(tt.complianceReportPath)
			assert.NoError(t, err)
			var cp ComplianceReport
			err = json.Unmarshal(complianceReport, &cp)
			assert.NoError(t, err)
			assert.True(t, reflect.DeepEqual(&cp, pp))

		})
	}
}
