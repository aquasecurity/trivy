package vex_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex"
)

func TestVEX_Filter(t *testing.T) {
	type fields struct {
		filePath string
		report   types.Report
	}
	type args struct {
		vulns []types.DetectedVulnerability
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []types.DetectedVulnerability
	}{
		{
			name: "OpenVEX",
			fields: fields{
				filePath: "testdata/openvex.json",
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2021-44228",
						PkgName:          "spring-boot",
						InstalledVersion: "2.6.0",
						PkgRef:           "pkg:maven/org.springframework.boot/spring-boot@2.6.0",
					},
				},
			},
			want: []types.DetectedVulnerability{},
		},
		{
			name: "CycloneDX SBOM with OpenVEX",
			fields: fields{
				filePath: "testdata/openvex.cdx.json",
				report: types.Report{
					CycloneDX: &ftypes.CycloneDX{
						SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
						Version:      1,
					},
				},
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2018-7489",
						PkgName:          "jackson-databind",
						InstalledVersion: "2.8.0",
						PkgRef:           "jackson-databind-2.8.0",
					},
					{
						VulnerabilityID:  "CVE-2018-7490",
						PkgName:          "jackson-databind",
						InstalledVersion: "2.8.0",
						PkgRef:           "jackson-databind-2.8.0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2018-7490",
					PkgName:          "jackson-databind",
					InstalledVersion: "2.8.0",
					PkgRef:           "jackson-databind-2.8.0",
				},
			},
		},
		{
			name: "CycloneDX SBOM with CycloneDX VEX",
			fields: fields{
				filePath: "testdata/cyclonedx.json",
				report: types.Report{
					CycloneDX: &ftypes.CycloneDX{
						SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
						Version:      1,
					},
				},
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2018-7489",
						PkgName:          "jackson-databind",
						InstalledVersion: "2.8.0",
						PkgRef:           "jackson-databind-2.8.0",
					},
					{
						VulnerabilityID:  "CVE-2018-7490",
						PkgName:          "jackson-databind",
						InstalledVersion: "2.8.0",
						PkgRef:           "jackson-databind-2.8.0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2018-7490",
					PkgName:          "jackson-databind",
					InstalledVersion: "2.8.0",
					PkgRef:           "jackson-databind-2.8.0",
				},
			},
		},
		{
			name: "CycloneDX VEX wrong URN",
			fields: fields{
				filePath: "testdata/cyclonedx.json",
				report: types.Report{
					CycloneDX: &ftypes.CycloneDX{
						SerialNumber: "urn:uuid:wrong",
						Version:      1,
					},
				},
			},
			args: args{
				vulns: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2018-7489",
						PkgName:          "jackson-databind",
						InstalledVersion: "2.8.0",
						PkgRef:           "jackson-databind-2.8.0",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2018-7489",
					PkgName:          "jackson-databind",
					InstalledVersion: "2.8.0",
					PkgRef:           "jackson-databind-2.8.0",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := vex.New(tt.fields.filePath, tt.fields.report)
			require.NoError(t, err)
			assert.Equal(t, tt.want, v.Filter(tt.args.vulns))
		})
	}
}
