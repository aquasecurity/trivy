package spec_test

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestGetScannerTypes(t *testing.T) {
	tests := []struct {
		name     string
		specPath string
		want     []types.SecurityCheck
	}{
		{name: "config scanner", specPath: "./testdata/spec.yaml", want: []types.SecurityCheck{types.SecurityCheckConfig}},
		{name: "config and vuln scanners", specPath: "./testdata/multi_scanner_spec.yaml", want: []types.SecurityCheck{types.SecurityCheckConfig, types.SecurityCheckVulnerability}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := ReadSpecFile(tt.specPath)
			assert.NoError(t, err)
			got := spec.GetScannerTypes(cr.Spec.Controls)
			assert.Equal(t, got, tt.want)
		})
	}
}

func TestCheckIDs(t *testing.T) {
	tests := []struct {
		name       string
		specPath   string
		wantConfig int
	}{
		{name: "check IDs list", specPath: "./testdata/spec.yaml", wantConfig: 29},
		{name: "check IDs list with dup values", specPath: "./testdata/spec_dup_id.yaml", wantConfig: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr, err := ReadSpecFile(tt.specPath)
			assert.NoError(t, err)
			got := spec.ScannerCheckIDs(cr.Spec.Controls)
			assert.Equal(t, len(got["config"]), tt.wantConfig)
		})
	}
}
