package photon_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/photon"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		osVer string
		pkgs  []ftypes.Package
	}
	tests := []struct {
		name     string
		args     args
		fixtures []string
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name:     "happy path",
			fixtures: []string{"testdata/fixtures/photon.yaml"},
			args: args{
				osVer: "1.0",
				pkgs: []ftypes.Package{
					{
						Name:       "PyYAML",
						Version:    "3.12",
						Release:    "4.ph1",
						SrcName:    "PyYAML",
						SrcVersion: "3.12",
						SrcRelease: "4.ph1",
						Layer: ftypes.Layer{
							DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
						},
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "PyYAML",
					VulnerabilityID:  "CVE-2020-1747",
					InstalledVersion: "3.12-4.ph1",
					FixedVersion:     "3.12-5.ph1",
					Layer: ftypes.Layer{
						DiffID: "sha256:932da51564135c98a49a34a193d6cd363d8fa4184d957fde16c9d8527b3f3b02",
					},
				},
			},
		},
		{
			name:     "invalid bucket",
			fixtures: []string{"testdata/fixtures/invalid.yaml"},
			args: args{
				osVer: "1.0",
				pkgs: []ftypes.Package{
					{
						Name:       "PyYAML",
						Version:    "3.12",
						SrcName:    "PyYAML",
						SrcVersion: "3.12",
					},
				},
			},
			wantErr: "failed to get Photon advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := photon.NewScanner()
			got, err := s.Detect(tt.args.osVer, tt.args.pkgs)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
