package spec_test

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

type fakeCache struct {
	defaultdirFunc            func() string
	getChecksDirFunc          func() string
	getComplianceSpecsDirFunc func() string
}

func (f fakeCache) DefaultDir() string {
	return f.defaultdirFunc()
}

func (f fakeCache) GetChecksDir() string {
	return f.getChecksDirFunc()
}

func (f fakeCache) GetComplianceSpecsDir() string {
	return f.getComplianceSpecsDirFunc()
}

func TestComplianceSpec_Scanners(t *testing.T) {
	tests := []struct {
		name    string
		spec    iacTypes.Spec
		want    types.Scanners
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "get config scanner type by check id prefix",
			spec: iacTypes.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []iacTypes.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []iacTypes.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []iacTypes.SpecCheck{
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
			spec: iacTypes.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []iacTypes.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []iacTypes.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []iacTypes.SpecCheck{
							{ID: "AVD-1.2.31"},
							{ID: "AVD-1.2.32"},
						},
					},
					{
						Name:        "Ensure no critical vulnerabilities",
						Description: "Control checks whether critical vulnerabilities are not found",
						ID:          "7.0",
						Checks: []iacTypes.SpecCheck{
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
			spec: iacTypes.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []iacTypes.Control{
					{
						Name: "Unknown",
						ID:   "1.0",
						Checks: []iacTypes.SpecCheck{
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
		spec iacTypes.Spec
		want map[types.Scanner][]string
	}{
		{
			name: "get config scanner type by check id prefix",
			spec: iacTypes.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []iacTypes.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []iacTypes.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []iacTypes.SpecCheck{
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
			spec: iacTypes.Spec{
				ID:          "1234",
				Title:       "NSA",
				Description: "National Security Agency - Kubernetes Hardening Guidance",
				RelatedResources: []string{
					"https://example.com",
				},
				Version: "1.0",
				Controls: []iacTypes.Control{
					{
						Name:        "Non-root containers",
						Description: "Check that container is not running as root",
						ID:          "1.0",
						Checks: []iacTypes.SpecCheck{
							{ID: "AVD-KSV012"},
						},
					},
					{
						Name:        "Check that encryption resource has been set",
						Description: "Control checks whether encryption resource has been set",
						ID:          "1.1",
						Checks: []iacTypes.SpecCheck{
							{ID: "AVD-1.2.31"},
							{ID: "AVD-1.2.32"},
						},
					},
					{
						Name:        "Ensure no critical vulnerabilities",
						Description: "Control checks whether critical vulnerabilities are not found",
						ID:          "7.0",
						Checks: []iacTypes.SpecCheck{
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

func TestComplianceSpec_LoadFromDiskBundle(t *testing.T) {

	t.Run("load user specified spec from disk", func(t *testing.T) {
		cs, err := spec.GetComplianceSpec(filepath.Join("@testdata", "testcache", "content", "specs", "compliance", "testspec.yaml"), cache.RealCache{})
		require.NoError(t, err)
		assert.Equal(t, spec.ComplianceSpec{Spec: iacTypes.Spec{
			ID:          "test-spec-1.2",
			Title:       "Test Spec",
			Description: "This is a test spec",
			RelatedResources: []string{
				"https://www.google.ca",
			},
			Version: "1.2",
			Controls: []iacTypes.Control{
				{
					Name:        "moar-testing",
					Description: "Test needs foo bar baz",
					ID:          "1.1",
					Checks: []iacTypes.SpecCheck{
						{ID: "AVD-TEST-1234"},
					},
					Severity: "LOW",
				},
			},
		}}, cs)
	})

	t.Run("load user specified spec from disk fails", func(t *testing.T) {
		_, err := spec.GetComplianceSpec("@doesnotexist", cache.RealCache{})
		assert.Contains(t, err.Error(), "error retrieving compliance spec from specified path")
	})

	t.Run("bundle does not exist", func(t *testing.T) {
		cs, err := spec.GetComplianceSpec("aws-cis-1.2", cache.RealCache{})
		require.NoError(t, err)
		assert.Equal(t, "aws-cis-1.2", cs.Spec.ID)
	})

	t.Run("bundle is corrupted", func(t *testing.T) {
		cs, err := spec.GetComplianceSpec("aws-cis-1.2", fakeCache{
			getChecksDirFunc: func() string {
				return "does not exist"
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "aws-cis-1.2", cs.Spec.ID)
	})

	t.Run("load spec from disk", func(t *testing.T) {
		cs, err := spec.GetComplianceSpec("testspec", fakeCache{
			getChecksDirFunc: func() string {
				return filepath.Join("testdata", "testcache")
			},
			getComplianceSpecsDirFunc: func() string {
				return filepath.Join("testdata", "testcache", "content", "specs", "compliance")
			},
		})
		require.NoError(t, err)
		assert.Equal(t, "test-spec-1.2", cs.Spec.ID)
	})

	t.Run("load spec from disk fails if bundle not found", func(t *testing.T) {
		_, err := spec.GetComplianceSpec("testspec", fakeCache{
			getChecksDirFunc: func() string {
				return filepath.Join("testdata", "testcache")
			},
			getComplianceSpecsDirFunc: func() string {
				return "does not exist"
			},
		})
		assert.Contains(t, err.Error(), "error retrieving compliance spec from bundle testspec")
	})

	// TODO: Add check to cover spec yaml unmarshal failure
}
