package vex

import (
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	openvex "github.com/openvex/go-vex/pkg/vex"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	type args struct {
		filePath string
	}
	tests := []struct {
		name    string
		args    args
		want    VEX
		wantErr bool
	}{
		{
			name: "CycloneDX JSON",
			args: args{
				filePath: "testdata/cyclonedx.json",
			},
			want: &CycloneDX{
				BOM: &cdx.BOM{
					XMLNS:       "http://cyclonedx.org/schema/bom/1.4",
					BOMFormat:   "CycloneDX",
					SpecVersion: cdx.SpecVersion1_4,
					Version:     1,
					Vulnerabilities: &[]cdx.Vulnerability{
						{
							ID: "CVE-2018-7489",
							Source: &cdx.Source{
								Name: "NVD",
								URL:  "https://nvd.nist.gov/vuln/detail/CVE-2019-9997",
							},
							Analysis: &cdx.VulnerabilityAnalysis{
								State:         "not_affected",
								Justification: "code_not_reachable",
							},
							Affects: &[]cdx.Affects{
								{
									Ref: "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#jackson-databind-2.8.0",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "OpenVEX JSON",
			args: args{
				filePath: "testdata/openvex.json",
			},
			want: &OpenVEX{
				VEX: &openvex.VEX{
					Metadata: openvex.Metadata{
						Context:    "https://openvex.dev/ns",
						Author:     "Aqua Security",
						AuthorRole: "Project Release Bot",
						Version:    "1",
						Timestamp:  lo.ToPtr(lo.Must(time.Parse(time.RFC3339Nano, "2023-01-16T19:07:16.853479631-06:00"))),
					},
					Statements: []openvex.Statement{
						{
							Vulnerability: "CVE-2021-44228",
							Products: []string{
								"pkg:maven/org.springframework.boot/spring-boot@2.6.0",
							},
							Status:        openvex.StatusNotAffected,
							Justification: "vulnerable_code_not_in_execute_path",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unknown format",
			args: args{
				filePath: "testdata/unknown.json",
			},
			wantErr: true,
		},
		{
			name: "no such file",
			args: args{
				filePath: "testdata/non_existent.json",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Open(tt.args.filePath)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestOpenVEX_Statement(t *testing.T) {
	type fields struct {
		VEX *openvex.VEX
	}
	type args struct {
		vulnID string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   Statement
	}{
		{
			name: "happy",
			fields: fields{
				VEX: &openvex.VEX{
					Statements: []openvex.Statement{
						{
							Vulnerability: "CVE-2021-44228",
							Products: []string{
								"pkg:maven/org.springframework.boot/spring-boot@2.6.0",
							},
							Status:        openvex.StatusNotAffected,
							Justification: "vulnerable_code_not_in_execute_path",
						},
					},
				},
			},
			args: args{
				vulnID: "CVE-2021-44228",
			},
			want: Statement{
				VulnerabilityID: "CVE-2021-44228",
				Affects:         []string{"pkg:maven/org.springframework.boot/spring-boot@2.6.0"},
				Status:          StatusNotAffected,
				Justification:   "vulnerable_code_not_in_execute_path",
			},
		},
		{
			name: "not match",
			fields: fields{
				VEX: &openvex.VEX{
					Statements: []openvex.Statement{
						{
							Vulnerability: "CVE-2021-44228",
							Products: []string{
								"pkg:maven/org.springframework.boot/spring-boot@2.6.0",
							},
							Status:        openvex.StatusNotAffected,
							Justification: "vulnerable_code_not_in_execute_path",
						},
					},
				},
			},
			args: args{
				vulnID: "CVE-3000-0001",
			},
			want: Statement{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &OpenVEX{
				VEX: tt.fields.VEX,
			}
			assert.Equal(t, tt.want, v.Statement(tt.args.vulnID))
		})
	}
}

func TestCycloneDX_Statement(t *testing.T) {
	type fields struct {
		BOM *cdx.BOM
	}
	type args struct {
		vulnID string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   Statement
	}{
		{
			name: "happy",
			fields: fields{
				BOM: &cdx.BOM{
					Vulnerabilities: &[]cdx.Vulnerability{
						{
							ID: "CVE-2018-7489",
							Analysis: &cdx.VulnerabilityAnalysis{
								State:         "not_affected",
								Justification: "code_not_reachable",
							},
							Affects: &[]cdx.Affects{
								{
									Ref: "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#jackson-databind-2.8.0",
								},
							},
						},
					},
				},
			},
			args: args{
				vulnID: "CVE-2018-7489",
			},
			want: Statement{
				VulnerabilityID: "CVE-2018-7489",
				Affects:         []string{"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#jackson-databind-2.8.0"},
				Status:          StatusNotAffected,
				Justification:   "code_not_reachable",
			},
		},
		{
			name: "not match",
			fields: fields{
				BOM: &cdx.BOM{
					Vulnerabilities: &[]cdx.Vulnerability{
						{
							ID: "CVE-2018-7489",
							Analysis: &cdx.VulnerabilityAnalysis{
								State:         "not_affected",
								Justification: "code_not_reachable",
							},
							Affects: &[]cdx.Affects{
								{
									Ref: "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#jackson-databind-2.8.0",
								},
							},
						},
					},
				},
			},
			args: args{
				vulnID: "CVE-3000-0001",
			},
			want: Statement{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &CycloneDX{
				BOM: tt.fields.BOM,
			}
			assert.Equal(t, tt.want, v.Statement(tt.args.vulnID))
		})
	}
}
