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

var dhiSource = &dbTypes.DataSource{
	ID:   "dhi",
	Name: "Docker Hardened Images Advisories",
	URL:  "https://github.com/docker-hardened-images/advisories",
}

func apkPkg(name, ver, arch string) ftypes.Package {
	return ftypes.Package{
		Name: name, Version: ver, SrcName: name, SrcVersion: ver, Arch: arch,
		AnalyzedBy: analyzer.TypeApk,
		Identifier: ftypes.PkgIdentifier{PURL: &packageurl.PackageURL{Type: packageurl.TypeApk, Namespace: "dhi", Name: name, Version: ver}},
	}
}

func debPkg(name, ver, arch string) ftypes.Package {
	return ftypes.Package{
		Name: name, Version: ver, SrcName: name, SrcVersion: ver, Arch: arch,
		AnalyzedBy: analyzer.TypeDpkg,
		Identifier: ftypes.PkgIdentifier{PURL: &packageurl.PackageURL{Type: packageurl.TypeDebian, Namespace: "dhi", Name: name, Version: ver}},
	}
}

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
			pkg:   apkPkg("coreutils", "9.11-r0", "aarch64"),
			want: []types.DetectedVulnerability{{
				VulnerabilityID: "DHI-CVE-2016-2781-coreutils", PkgName: "coreutils", InstalledVersion: "9.11-r0", FixedVersion: "9.11-r1",
				PkgIdentifier: apkPkg("coreutils", "9.11-r0", "aarch64").Identifier,
				DataSource:    dhiSource,
			}},
		},
		{
			name:  "Alpine package at the fixed version is not affected",
			osVer: "3.24",
			pkg:   apkPkg("coreutils", "9.11-r1", "aarch64"),
		},
		{
			name:  "Alpine package above the fixed version is not affected",
			osVer: "3.24",
			pkg:   apkPkg("coreutils", "9.12-r0", "aarch64"),
		},
		{
			name:  "unfixed advisory applies to any version",
			osVer: "3.24",
			pkg:   apkPkg("busybox", "1.37.0-r30", "aarch64"),
			want: []types.DetectedVulnerability{{
				VulnerabilityID: "DHI-CVE-2099-0001-busybox", PkgName: "busybox", InstalledVersion: "1.37.0-r30",
				PkgIdentifier: apkPkg("busybox", "1.37.0-r30", "aarch64").Identifier,
				DataSource:    dhiSource,
			}},
		},
		{
			name:  "version inside the second of two ranges is affected",
			osVer: "3.24",
			pkg:   apkPkg("openssl", "3.5.2-r0", "aarch64"),
			want: []types.DetectedVulnerability{{
				VulnerabilityID: "DHI-CVE-2099-0002-openssl", PkgName: "openssl", InstalledVersion: "3.5.2-r0", FixedVersion: "3.5.1-r0, 3.5.3-r0",
				PkgIdentifier: apkPkg("openssl", "3.5.2-r0", "aarch64").Identifier,
				DataSource:    dhiSource,
			}},
		},
		{
			name:  "version between two ranges is not affected",
			osVer: "3.24",
			pkg:   apkPkg("openssl", "3.5.1-r0", "aarch64"),
		},
		{
			name:  "affected Debian DHI package",
			osVer: "13",
			pkg:   debPkg("coreutils", "9.7-3+dhi3", "arm64"),
			want: []types.DetectedVulnerability{{
				VulnerabilityID: "DHI-CVE-2017-18018-coreutils", PkgName: "coreutils", InstalledVersion: "9.7-3+dhi3", FixedVersion: "9.7-3+dhi4",
				PkgIdentifier: debPkg("coreutils", "9.7-3+dhi3", "arm64").Identifier,
				DataSource:    dhiSource,
			}},
		},
		{
			name:  "Debian package at the fixed version is not affected",
			osVer: "13",
			pkg:   debPkg("coreutils", "9.7-3+dhi4", "arm64"),
		},
		{
			name:  "different architecture is isolated",
			osVer: "3.24",
			pkg:   apkPkg("coreutils", "9.11-r0", "x86_64"),
		},
		{
			name:  "different release is isolated",
			osVer: "3.25",
			pkg:   apkPkg("coreutils", "9.11-r0", "aarch64"),
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
