package composer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/library/composer"
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
				pkgName: "aws/aws-sdk-php",
				pkgVer:  "3.2.0",
			},
			fixtures: []string{"testdata/fixtures/composer.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "aws/aws-sdk-php",
					InstalledVersion: "3.2.0",
					VulnerabilityID:  "CVE-2015-5723",
					FixedVersion:     "3.2.1",
				},
			},
		},
		{
			name: "not detected",
			args: args{
				pkgName: "guzzlehttp/guzzle",
				pkgVer:  "5.3.1",
			},
			fixtures: []string{"testdata/fixtures/composer.yaml"},
			want:     nil,
		},
		{
			name: "malformed JSON",
			args: args{
				pkgName: "aws/aws-sdk-php",
				pkgVer:  "3.2.0",
			},
			fixtures: []string{"testdata/fixtures/invalid-type.yaml"},
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			a := composer.NewAdvisory()
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
