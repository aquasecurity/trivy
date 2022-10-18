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

func TestJSONReport(t *testing.T) {
	tests := []struct {
		name               string
		specPath           string
		resultPath         string
		reportType         string
		wantJsonReportPath string
	}{
		{name: "build json report summary", specPath: "./testdata/config_spec.yaml", reportType: "summary", resultPath: "./testdata/results_config.json", wantJsonReportPath: "./testdata/json_summary.json"},
		{name: "build json report", specPath: "./testdata/config_spec.yaml", reportType: "all", resultPath: "./testdata/results_config.json", wantJsonReportPath: "./testdata/json_view.json"},
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
			assert.NoError(t, err)
			ioWriter := new(bytes.Buffer)
			tr := JSONWriter{Report: tt.reportType, Output: ioWriter}
			err = tr.Write(complianceResults)
			assert.NoError(t, err)
			bt, err := io.ReadAll(ioWriter)
			assert.NoError(t, err)
			r, err := os.ReadFile(tt.wantJsonReportPath)
			assert.NoError(t, err)
			assert.Equal(t, string(bt), string(r))
		})
	}
}
