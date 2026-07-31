package dhi_test

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/internal/dbtest"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/dhi"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestScannerDetect(t *testing.T) {
	tests := []struct {
		name  string
		osVer string
		pkg   ftypes.Package
		want  []types.DetectedVulnerability
	}{
		{
			name:  "affected Alpine DHI package",
			osVer: "3.24",
			pkg: ftypes.Package{
				Name: "coreutils", Version: "9.11-r0", SrcName: "coreutils", SrcVersion: "9.11-r0", Arch: "aarch64",
				AnalyzedBy: analyzer.TypeApk,
				Identifier: ftypes.PkgIdentifier{PURL: &packageurl.PackageURL{Type: packageurl.TypeApk, Namespace: "dhi", Name: "coreutils", Version: "9.11-r0"}},
			},
			want: []types.DetectedVulnerability{{
				VulnerabilityID: "DHI-CVE-2016-2781-coreutils", PkgName: "coreutils", InstalledVersion: "9.11-r0", FixedVersion: "9.11-r1",
				PkgIdentifier: ftypes.PkgIdentifier{PURL: &packageurl.PackageURL{Type: packageurl.TypeApk, Namespace: "dhi", Name: "coreutils", Version: "9.11-r0"}},
				DataSource:    &dbTypes.DataSource{ID: "dhi", Name: "Docker Hardened Images Advisories", URL: "https://github.com/docker-hardened-images/advisories"},
			}},
		},
		{
			name:  "affected Debian DHI package",
			osVer: "13",
			pkg: ftypes.Package{
				Name: "coreutils", Version: "9.7-3+dhi3", SrcName: "coreutils", SrcVersion: "9.7-3+dhi3", Arch: "arm64",
				AnalyzedBy: analyzer.TypeDpkg,
				Identifier: ftypes.PkgIdentifier{PURL: &packageurl.PackageURL{Type: packageurl.TypeDebian, Namespace: "dhi", Name: "coreutils", Version: "9.7-3+dhi3"}},
			},
			want: []types.DetectedVulnerability{{
				VulnerabilityID: "DHI-CVE-2017-18018-coreutils", PkgName: "coreutils", InstalledVersion: "9.7-3+dhi3", FixedVersion: "9.7-3+dhi4",
				PkgIdentifier: ftypes.PkgIdentifier{PURL: &packageurl.PackageURL{Type: packageurl.TypeDebian, Namespace: "dhi", Name: "coreutils", Version: "9.7-3+dhi3"}},
				DataSource:    &dbTypes.DataSource{ID: "dhi", Name: "Docker Hardened Images Advisories", URL: "https://github.com/docker-hardened-images/advisories"},
			}},
		},
		{
			name:  "different architecture is isolated",
			osVer: "3.24",
			pkg:   ftypes.Package{Name: "coreutils", Version: "9.11-r0", SrcName: "coreutils", SrcVersion: "9.11-r0", Arch: "x86_64", AnalyzedBy: analyzer.TypeApk},
		},
		{
			name:  "different release is isolated",
			osVer: "3.25",
			pkg:   ftypes.Package{Name: "coreutils", Version: "9.11-r0", SrcName: "coreutils", SrcVersion: "9.11-r0", Arch: "aarch64", AnalyzedBy: analyzer.TypeApk},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_ = dbtest.InitDB(t, []string{"testdata/fixtures/dhi.yaml", "testdata/fixtures/data-source.yaml"})
			defer db.Close()

			got, err := dhi.NewScanner().Detect(t.Context(), tt.osVer, nil, []ftypes.Package{tt.pkg})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
