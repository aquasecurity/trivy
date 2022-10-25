package spec_test

import (
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestComplianceSpec_SecurityChecks(t *testing.T) {
	tests := []struct {
		name    string
		spec    spec.Spec
		want    []types.SecurityCheck
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "get config scanner type by check id prefix",
			spec: spec.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []spec.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []spec.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []spec.SpecCheck{
							{ID: "AVD-1.2.31"},
							{ID: "AVD-1.2.32"},
						},
					},
				},
			},
			want:    []types.SecurityCheck{types.SecurityCheckConfig},
			wantErr: assert.NoError,
		},
		{
			name: "get config and vuln scanners types by check id prefix",
			spec: spec.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []spec.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []spec.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []spec.SpecCheck{
							{ID: "AVD-1.2.31"},
							{ID: "AVD-1.2.32"},
						},
					},
					{
						Name:        "Ensure no critical vulnerabilities",
						Description: "Control checks whether critical vulnerabilities are not found",
						ID:          "7.0",
						Checks: []spec.SpecCheck{
							{ID: "CVE-9999-9999"},
						},
					},
				},
			},
			want:    []types.SecurityCheck{types.SecurityCheckConfig, types.SecurityCheckVulnerability},
			wantErr: assert.NoError,
		},
		{
			name: "unknown prefix",
			spec: spec.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []spec.Control{
					{
						Name: "Unknown",
						ID:   "1.0",
						Checks: []spec.SpecCheck{
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
			got, err := cs.SecurityChecks()
			if !tt.wantErr(t, err, fmt.Sprintf("SecurityChecks()")) {
				return
			}
			sort.Strings(got) // for consistency
			assert.Equalf(t, tt.want, got, "SecurityChecks()")
		})
	}
}

func TestComplianceSpec_CheckIDs(t *testing.T) {
	tests := []struct {
		name string
		spec spec.Spec
		want map[types.SecurityCheck][]string
	}{
		{
			name: "get config scanner type by check id prefix",
			spec: spec.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []spec.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []spec.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []spec.SpecCheck{
							{ID: "AVD-1.2.31"},
							{ID: "AVD-1.2.32"},
						},
					},
				},
			},
			want: map[types.SecurityCheck][]string{
				types.SecurityCheckConfig: {
					"AVD-KSV012",
					"AVD-1.2.31",
					"AVD-1.2.32",
				},
			},
		},
		{
			name: "get config and vuln scanners types by check id prefix",
			spec: spec.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []spec.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []spec.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []spec.SpecCheck{
							{ID: "AVD-1.2.31"},
							{ID: "AVD-1.2.32"},
						},
					},
					{
						Name:        "Ensure no critical vulnerabilities",
						Description: "Control checks whether critical vulnerabilities are not found",
						ID:          "7.0",
						Checks: []spec.SpecCheck{
							{ID: "CVE-9999-9999"},
						},
					},
				},
			},
			want: map[types.SecurityCheck][]string{
				types.SecurityCheckConfig: {
					"AVD-KSV012",
					"AVD-1.2.31",
					"AVD-1.2.32",
				},
				types.SecurityCheckVulnerability: {
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
