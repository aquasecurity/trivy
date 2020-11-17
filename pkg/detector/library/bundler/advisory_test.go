package bundler_test

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/detector/library/bundler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
				pkgName: "activesupport",
				pkgVer:  "4.1.1",
			},
			fixtures: []string{"testdata/fixtures/gem.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "activesupport",
					InstalledVersion: "4.1.1",
					VulnerabilityID:  "CVE-2015-3226",
					FixedVersion:     ">= 4.2.2, ~> 4.1.11",
				},
			},
		},
		{
			name: "not detected",
			args: args{
				pkgName: "activesupport",
				pkgVer:  "4.1.0.a",
			},
			fixtures: []string{"testdata/fixtures/gem.yaml"},
			want:     nil,
		},
		{
			name: "invalid JSON",
			args: args{
				pkgName: "activesupport",
				pkgVer:  "4.1.0",
			},
			fixtures: []string{"testdata/fixtures/invalid-type.yaml"},
			want:     nil,
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}

	log.InitLogger(false, true)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := utils.InitTestDB(t, tt.fixtures)
			defer os.RemoveAll(dir)

			a := bundler.NewAdvisory()
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
