package report

import (
	"bytes"
	"encoding/json"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"testing"
)

func TestTableReport(t *testing.T) {
	tests := []struct {
		name                  string
		specPath              string
		resultPath            string
		reportType            string
		wantSummaryReportPath string
	}{
		{name: "build table report summary config only", specPath: "./testdata/config_spec.yaml", reportType: "summary", resultPath: "./testdata/results_config.json", wantSummaryReportPath: "./testdata/table_summary.txt"},
		{name: "build table report summary config and vuln", specPath: "./testdata/config_vuln_spec.yaml", reportType: "summary", resultPath: "./testdata/results_vul_config.json", wantSummaryReportPath: "./testdata/vuln_conf_table_summary.txt"},
		{name: "build table report config only", specPath: "./testdata/config_spec.yaml", reportType: "all", resultPath: "./testdata/results_config.json", wantSummaryReportPath: "./testdata/table.txt"},
		{name: "build table report config and vuln", specPath: "./testdata/config_vuln_spec.yaml", reportType: "all", resultPath: "./testdata/results_vul_config.json", wantSummaryReportPath: "./testdata/vuln_conf_table.txt"},
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
			tr := TableWriter{Report: tt.reportType, Output: ioWriter}
			err = tr.Write(complianceResults)
			assert.NoError(t, err)
			bt, err := io.ReadAll(ioWriter)
			assert.NoError(t, err)
			r, err := os.ReadFile(tt.wantSummaryReportPath)
			assert.NoError(t, err)
			assert.Equal(t, string(bt), string(r))
		})
	}
}

func TestColumn(t *testing.T) {
	tr := TableWriter{}
	assert.Equal(t, tr.Columns(), []string{ControlIDColumn, SeverityColumn, ControlNameColumn, ComplianceColumn})
}
