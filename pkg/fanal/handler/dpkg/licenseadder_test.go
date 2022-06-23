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
				},
				CustomResources: []types.CustomResource{
					{
						Type:     dpkg.LicenseAdder,
						FilePath: "base-files",
						Data:     "GPL",
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
