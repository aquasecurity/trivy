package osv_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	osvSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/osv"
	"github.com/aquasecurity/trivy/pkg/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
	"github.com/aquasecurity/trivy/pkg/detector/library/osv"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestAdvisory_DetectVulnerabilities(t *testing.T) {
	type fields struct {
		ecosystem string
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
			name: "PyPI detected",
			fields: fields{
				ecosystem: osvSrc.Python,
				comparer:  comparer.GenericComparer{},
			},
			args: args{
				pkgName: "bikeshed",
				pkgVer:  "2.0.0",
			},
			fixtures: []string{"testdata/fixtures/osv.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "bikeshed",
					InstalledVersion: "2.0.0",
					VulnerabilityID:  "CVE-2021-23422",
					FixedVersion:     "3.0.0",
				},
			},
		},
		{
			name: "Go detected",
			fields: fields{
				ecosystem: osvSrc.Go,
				comparer:  comparer.GenericComparer{},
			},
			args: args{
				pkgName: "github.com/evanphx/json-patch",
				pkgVer:  "0.5.1",
			},
			fixtures: []string{"testdata/fixtures/osv.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "github.com/evanphx/json-patch",
					InstalledVersion: "0.5.1",
					VulnerabilityID:  "CVE-2018-14632",
					FixedVersion:     "0.5.2",
				},
			},
		},
		{
			name: "crates.io detected",
			fields: fields{
				ecosystem: osvSrc.Rust,
				comparer:  comparer.GenericComparer{},
			},
			args: args{
				pkgName: "internment",
				pkgVer:  "0.3.14",
			},
			fixtures: []string{"testdata/fixtures/osv.yaml"},
			want: []types.DetectedVulnerability{
				{
					PkgName:          "internment",
					InstalledVersion: "0.3.14",
					VulnerabilityID:  "CVE-2020-35874",
					FixedVersion:     "0.4.0",
				},
			},
		},
		{
			name: "not detected vuln",
			fields: fields{
				ecosystem: osvSrc.Python,
				comparer:  comparer.GenericComparer{},
			},
			args: args{
				pkgName: "bikeshed",
				pkgVer:  "3.0.0",
			},
			fixtures: []string{"testdata/fixtures/osv.yaml"},
			want:     nil,
		},
		{
			name: "malformed JSON",
			fields: fields{
				ecosystem: osvSrc.Python,
				comparer:  comparer.GenericComparer{},
			},
			args: args{
				pkgName: "bikeshed",
				pkgVer:  "3.0.0",
			},
			fixtures: []string{"testdata/fixtures/invalid-type.yaml"},
			wantErr:  "failed to unmarshal advisory JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, tt.fixtures)
			defer db.Close()

			a := osv.NewAdvisory(tt.fields.ecosystem, tt.fields.comparer)
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
