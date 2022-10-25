package report_test

import (
	"testing"
)

func TestBuildComplianceReport(t *testing.T) {
	// TODO
	//tests := []struct {
	//	name                 string
	//	specPath             string
	//	resultPath           string
	//	complianceReportPath string
	//}{
	//	{name: "build report test config and vuln", specPath: "./testdata/config_vuln_spec.yaml", resultPath: "./testdata/results_vul_config.json", complianceReportPath: "./testdata/vuln_config_compliance.json"}}
	//
	//for _, tt := range tests {
	//	t.Run(tt.name, func(t *testing.T) {
	//		specFile, err := os.ReadFile(tt.specPath)
	//		assert.NoError(t, err)
	//		var res types.Results
	//		c, err := os.ReadFile(tt.resultPath)
	//		err = json.Unmarshal(c, &res)
	//		assert.NoError(t, err)
	//		pp, err := BuildComplianceReport([]types.Results{res}, string(specFile))
	//		assert.NoError(t, err)
	//		complianceReport, err := os.ReadFile(tt.complianceReportPath)
	//		assert.NoError(t, err)
	//		var cp ComplianceReport
	//		err = json.Unmarshal(complianceReport, &cp)
	//		assert.NoError(t, err)
	//		assert.True(t, reflect.DeepEqual(&cp, pp))
	//
	//	})
	//}
}
