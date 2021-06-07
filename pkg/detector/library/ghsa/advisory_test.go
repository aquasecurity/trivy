package ghsa_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	ghsaSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/ghsa"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/aquasecurity/trivy/pkg/detector/library/ghsa"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestAdvisory_DetectVulnerabilities(t *testing.T) {
	type fields struct {
		ecosystem ghsaSrc.Ecosystem
		comparer  comparer.Comparer
	}
	type args struct {
		pkgName string
		pkgVer  string
	}
	tests := []struct {
		name     string
		args     args
		fields   fields
		fixtures []string
		want     []types.DetectedVulnerability
		wantErr  string
	}{
		{
			name: "composer detected",
			fields: fields{
				ecosystem: ghsaSrc.Composer,
				comparer:  comparer.GenericComparer{},
			},
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "5.1.5-alpha",
			},
			fixtures: []string{"testdata/fixtures/ghsa.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "symfony/symfony",
					InstalledVersion: "5.1.5-alpha",
					VulnerabilityID:  "CVE-2020-15094",
					FixedVersion:     "5.1.5, 4.4.13",
				},
			},
		},
		{
			name: "nuget detected",
			fields: fields{
				ecosystem: ghsaSrc.Nuget,
				comparer:  comparer.GenericComparer{},
			},
			args: args{
				pkgName: "AWSSDK.Core",
				pkgVer:  "3.5.1.30",
			},
			fixtures: []string{"testdata/fixtures/ghsa.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "AWSSDK.Core",
					InstalledVersion: "3.5.1.30",
					VulnerabilityID:  "CVE-2020-99999",
					FixedVersion:     "3.5.1.31",
				},
			},
		},
		{
			name: "not detected",
			fields: fields{
				ecosystem: ghsaSrc.Composer,
				comparer:  comparer.GenericComparer{},
			},
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "5.1.5",
			},
			fixtures: []string{"testdata/fixtures/ghsa.yaml"},
			want:     nil,
		},
		{
			name: "malformed JSON",
			fields: fields{
				ecosystem: ghsaSrc.Composer,
				comparer:  comparer.GenericComparer{},
			},
			args: args{
				pkgName: "symfony/symfony",
				pkgVer:  "5.1.5",
			},
			fixtures: []string{"testdata/fixtures/invalid-type.yaml"},
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			a := ghsa.NewAdvisory(tt.fields.ecosystem, tt.fields.comparer)
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
