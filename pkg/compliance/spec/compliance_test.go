package spec_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestComplianceSpec_Scanners(t *testing.T) {
	tests := []struct {
		name    string
		spec    defsecTypes.Spec
		want    types.Scanners
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "get config scanner type by check id prefix",
			spec: defsecTypes.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []defsecTypes.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []defsecTypes.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []defsecTypes.SpecCheck{
							{ID: "AVD-1.2.31"},
							{ID: "AVD-1.2.32"},
						},
					},
				},
			},
			want:    []types.Scanner{types.MisconfigScanner},
			wantErr: assert.NoError,
		},
		{
			name: "get config and vuln scanners types by check id prefix",
			spec: defsecTypes.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []defsecTypes.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []defsecTypes.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []defsecTypes.SpecCheck{
							{ID: "AVD-1.2.31"},
							{ID: "AVD-1.2.32"},
						},
					},
					{
						Name:        "Ensure no critical vulnerabilities",
						Description: "Control checks whether critical vulnerabilities are not found",
						ID:          "7.0",
						Checks: []defsecTypes.SpecCheck{
							{ID: "CVE-9999-9999"},
						},
					},
				},
			},
			want: []types.Scanner{
				types.MisconfigScanner,
				types.VulnerabilityScanner,
			},
			wantErr: assert.NoError,
		},
		{
			name: "unknown prefix",
			spec: defsecTypes.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []defsecTypes.Control{
					{
						Name: "Unknown",
						ID:   "1.0",
						Checks: []defsecTypes.SpecCheck{
							{ID: "UNKNOWN-001"},
						},
					},
				},
			},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := &spec.ComplianceSpec{
				Spec: tt.spec,
			}
			got, err := cs.Scanners()
			if !tt.wantErr(t, err, "Scanners()") {
				return
			}
			sort.Slice(got, func(i, j int) bool {
				return got[i] < got[j]
			}) // for consistency
			assert.Equalf(t, tt.want, got, "Scanners()")
		})
	}
}

func TestComplianceSpec_CheckIDs(t *testing.T) {
	tests := []struct {
		name string
		spec defsecTypes.Spec
		want map[types.Scanner][]string
	}{
		{
			name: "get config scanner type by check id prefix",
			spec: defsecTypes.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []defsecTypes.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []defsecTypes.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []defsecTypes.SpecCheck{
							{ID: "AVD-1.2.31"},
							{ID: "AVD-1.2.32"},
						},
					},
				},
			},
			want: map[types.Scanner][]string{
				types.MisconfigScanner: {
					"AVD-KSV012",
					"AVD-1.2.31",
					"AVD-1.2.32",
				},
			},
		},
		{
			name: "get config and vuln scanners types by check id prefix",
			spec: defsecTypes.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []defsecTypes.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []defsecTypes.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []defsecTypes.SpecCheck{
							{ID: "AVD-1.2.31"},
							{ID: "AVD-1.2.32"},
						},
					},
					{
						Name:        "Ensure no critical vulnerabilities",
						Description: "Control checks whether critical vulnerabilities are not found",
						ID:          "7.0",
						Checks: []defsecTypes.SpecCheck{
							{ID: "CVE-9999-9999"},
						},
					},
				},
			},
			want: map[types.Scanner][]string{
				types.MisconfigScanner: {
					"AVD-KSV012",
					"AVD-1.2.31",
					"AVD-1.2.32",
				},
				types.VulnerabilityScanner: {
					"CVE-9999-9999",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := &spec.ComplianceSpec{
				Spec: tt.spec,
			}
			got := cs.CheckIDs()
			assert.Equalf(t, tt.want, got, "CheckIDs()")
		})
	}
}
