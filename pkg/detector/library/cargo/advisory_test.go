package cargo_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/library/cargo"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestAdvisory_DetectVulnerabilities(t *testing.T) {
	type args struct {
		pkgName string
		pkgVer  string
	}
	tests := []struct {
		name     string
		args     args
		fixtures []string
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name: "detected",
			args: args{
				pkgName: "bumpalo",
				pkgVer:  "3.2.0",
			},
			fixtures: []string{"testdata/fixtures/cargo.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "bumpalo",
					InstalledVersion: "3.2.0",
					VulnerabilityID:  "RUSTSEC-2020-0006",
					FixedVersion:     ">= 3.2.1",
				},
			},
		},
		{
			name: "not detected",
			args: args{
				pkgName: "bumpalo",
				pkgVer:  "3.2.1",
			},
			fixtures: []string{"testdata/fixtures/cargo.yaml"},
			want:     nil,
		},
		{
			name: "no patched version",
			args: args{
				pkgName: "bumpalo",
				pkgVer:  "3.2.0",
			},
			fixtures: []string{"testdata/fixtures/no-patched-version.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "bumpalo",
					InstalledVersion: "3.2.0",
					VulnerabilityID:  "RUSTSEC-2020-0006",
				},
			},
		},
		{
			name: "invalid JSON",
			args: args{
				pkgName: "bumpalo",
				pkgVer:  "3.2.1",
			},
			fixtures: []string{"testdata/fixtures/invalid-type.yaml"},
			want:     nil,
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			a := cargo.NewAdvisory()
			got, err := a.DetectVulnerabilities(tt.args.pkgName, tt.args.pkgVer)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
