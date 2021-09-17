package arch_test

import (
	"testing"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/arch"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner_Detect(t *testing.T) {
	type args struct {
		pkgs []ftypes.Package
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
			fixtures: []string{"testdata/fixtures/arch.yaml"},
			args: args{
				pkgs: []ftypes.Package{
					{
						Name:       "ansible",
						Version:    "2.2.0.0",
						Release:    "1",
						SrcName:    "ansible",
						SrcVersion: "2.2.0.0",
						SrcRelease: "1",
					},
					{
						Name:       "invalid",
						Version:    "invalid", // skipped
						SrcName:    "invalid",
						SrcVersion: "invalid",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "ansible",
					VulnerabilityID:  "CVE-2016-9587",
					InstalledVersion: "2.2.0.0-1",
					FixedVersion:     "2.2.1.0rc5-3",
				},
			},
		},
		{
			name:     "installVersion greater than affectedVersion",
			fixtures: []string{"testdata/fixtures/arch.yaml"},
			args: args{
				pkgs: []ftypes.Package{
					{
						Name:       "ansible",
						Version:    "2.1.2.0",
						Release:    "1",
						SrcName:    "ansible",
						SrcVersion: "2.1.2.0",
						SrcRelease: "1",
					},
				},
			},
			want: nil,
		},
		{
			name:     "installVersion not less then fixedVersion",
			fixtures: []string{"testdata/fixtures/arch.yaml"},
			args: args{
				pkgs: []ftypes.Package{
					{
						Name:       "ansible",
						Version:    "2.2.1.0rc5",
						Release:    "3",
						SrcName:    "ansible",
						SrcVersion: "2.2.1.0rc5",
						SrcRelease: "3",
					},
				},
			},
			want: nil,
		},
		{
			name:     "fixedVersion is empty",
			fixtures: []string{"testdata/fixtures/arch.yaml"},
			args: args{
				pkgs: []ftypes.Package{
					{
						Name:       "ansible",
						Version:    "3.1.0",
						Release:    "1",
						SrcName:    "ansible",
						SrcVersion: "3.1.0",
						SrcRelease: "1",
					},
				},
			},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "ansible",
					VulnerabilityID:  "CVE-2021-3447",
					InstalledVersion: "3.1.0-1",
					FixedVersion:     "",
				},
			},
		},
		{
			name:     "Get returns an error",
			fixtures: []string{"testdata/fixtures/invalid.yaml"},
			args: args{
				pkgs: []ftypes.Package{
					{
						Name:       "jq",
						Version:    "1.6-r0",
						SrcName:    "jq",
						SrcVersion: "1.6-r0",
					},
				},
			},
			wantErr: "failed to get arch advisories",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			s := arch.NewScanner()
			got, err := s.Detect("", tt.args.pkgs)
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
