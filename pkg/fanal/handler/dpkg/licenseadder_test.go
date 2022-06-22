package dpkg

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/dpkg"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
)

func TestDpkgLicenseHook_Hook(t *testing.T) {
	tests := []struct {
		name         string
		blob         *types.BlobInfo
		wantPackages *types.BlobInfo
	}{
		{
			name: "happy path.",
			blob: &types.BlobInfo{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/base",
						Packages: []types.Package{
							{Name: "base-files", Version: "9.9+deb9u9", SrcName: "base-files", SrcVersion: "9.9+deb9u9"},
						},
					},
					{
						FilePath: "var/lib/dpkg/status.d/libc6",
						Packages: []types.Package{
							{Name: "libc6", Version: "2.24-11+deb9u4", SrcName: "glibc", SrcVersion: "2.24-11+deb9u4"},
						},
					},
					{
						FilePath: "var/lib/dpkg/status.d/netbase",
						Packages: []types.Package{
							{Name: "netbase", Version: "5.4", SrcName: "netbase", SrcVersion: "5.4"},
						},
					},
					{
						FilePath: "var/lib/dpkg/status.d/tzdata",
						Packages: []types.Package{
							{Name: "tzdata", Version: "2019a-0+deb9u1", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1"},
						},
					},
				},
				CustomResources: []types.CustomResource{
					{
						Type:     dpkg.LicenseAdder,
						FilePath: "base-files",
						Data:     "GPL",
					},
					{
						Type:     dpkg.LicenseAdder,
						FilePath: "ca-certificates",
						Data:     "GPL-2+, GPL-2, MPL-2.0, GPL-2.0",
					},
					{
						Type:     dpkg.LicenseAdder,
						FilePath: "netbase",
						Data:     "GPL-2",
					},
					{
						Type:     dpkg.LicenseAdder,
						FilePath: "tzdata",
						Data:     "Unknown",
					},
					{
						FilePath: "usr/bin/pydoc",
						Data:     "remove",
					},
				},
			},
			wantPackages: &types.BlobInfo{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/base",
						Packages: []types.Package{
							{Name: "base-files", Version: "9.9+deb9u9", SrcName: "base-files", SrcVersion: "9.9+deb9u9", License: "GPL"},
						},
					},
					{
						FilePath: "var/lib/dpkg/status.d/libc6",
						Packages: []types.Package{
							{Name: "libc6", Version: "2.24-11+deb9u4", SrcName: "glibc", SrcVersion: "2.24-11+deb9u4", License: ""},
						},
					},
					{
						FilePath: "var/lib/dpkg/status.d/netbase",
						Packages: []types.Package{
							{Name: "netbase", Version: "5.4", SrcName: "netbase", SrcVersion: "5.4", License: "GPL-2"},
						},
					},
					{
						FilePath: "var/lib/dpkg/status.d/tzdata",
						Packages: []types.Package{
							{Name: "tzdata", Version: "2019a-0+deb9u1", SrcName: "tzdata", SrcVersion: "2019a-0+deb9u1", License: "Unknown"},
						},
					},
				},
				CustomResources: []types.CustomResource{
					{
						FilePath: "usr/bin/pydoc",
						Data:     "remove",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dpkgLicenseHook := dpkgLicensePostHandler{}
			a := &analyzer.AnalysisResult{}
			_ = dpkgLicenseHook.Handle(context.Background(), a, test.blob)

			assert.Equal(t, test.wantPackages, test.blob)
		})
	}
}
