package node_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/detector/library/node"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
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
				pkgName: "electron",
				pkgVer:  "2.0.17",
			},
			fixtures: []string{"testdata/fixtures/npm.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "electron",
					InstalledVersion: "2.0.17",
					VulnerabilityID:  "CVE-2019-5786",
					FixedVersion:     "^2.0.18, ^3.0.16, ^3.1.6, ^4.0.8, ^5.0.0-beta.5",
				},
			},
		},
		{
			name: "not detected",
			args: args{
				pkgName: "electron",
				pkgVer:  "2.0.18",
			},
			fixtures: []string{"testdata/fixtures/npm.yaml"},
			want:     nil,
		},
		{
			name: "empty value",
			args: args{
				pkgName: "electron",
				pkgVer:  "2.0.18",
			},
			fixtures: []string{"testdata/fixtures/no-value.yaml"},
			want:     nil,
		},
		{name: "malformed JSON",
			args: args{
				pkgName: "electron",
				pkgVer:  "2.0.18",
			},
			fixtures: []string{"testdata/fixtures/invalid-type.yaml"},
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}

	log.InitLogger(false, true)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := utils.InitTestDB(t, tt.fixtures)
			defer os.RemoveAll(dir)

			a := node.NewAdvisory()
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
