package python_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/library/python"
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
				pkgName: "django",
				pkgVer:  "2.2.11a1",
			},
			fixtures: []string{"testdata/fixtures/pip.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "django",
					InstalledVersion: "2.2.11a1",
					VulnerabilityID:  "CVE-2020-9402",
					FixedVersion:     "1.11.29, 2.2.11, 3.0.4",
				},
			},
		},
		{
			// https://github.com/aquasecurity/trivy/issues/713
			name: "not detected",
			args: args{
				pkgName: "django",
				pkgVer:  "3.0.10",
			},
			fixtures: []string{"testdata/fixtures/pip.yaml"},
			want:     nil,
		},
		{
			name: "malformed JSON",
			args: args{
				pkgName: "django",
				pkgVer:  "2.0.18",
			},
			fixtures: []string{"testdata/fixtures/invalid-type.yaml"},
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			a := python.NewAdvisory()
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
