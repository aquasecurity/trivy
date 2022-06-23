package dpkg

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestDpkgLicenseHook_Hook(t *testing.T) {
	tests := []struct {
		name string
		blob *types.BlobInfo
		want *types.BlobInfo
	}{
		{
			name: "happy path",
			blob: &types.BlobInfo{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/base",
						Packages: []types.Package{
							{
								Name:    "base-files",
								Version: "9.9+deb9u9",
							},
						},
					},
				},
				CustomResources: []types.CustomResource{
					{
						Type:     string(types.DpkgLicensePostHandler),
						FilePath: "usr/share/doc/base-files/copyright",
						Data:     "GPL",
					},
					{
						Type:     "my-custom",
						FilePath: "usr/bin/pydoc",
						Data:     "remove",
					},
				},
			},
			want: &types.BlobInfo{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/base",
						Packages: []types.Package{
							{
								Name:    "base-files",
								Version: "9.9+deb9u9",
								License: "GPL",
							},
						},
					},
				},
				CustomResources: []types.CustomResource{
					{
						Type:     "my-custom",
						FilePath: "usr/bin/pydoc",
						Data:     "remove",
					},
				},
			},
		},
		{
			name: "no license found",
			blob: &types.BlobInfo{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/base",
						Packages: []types.Package{
							{
								Name:    "base-files",
								Version: "9.9+deb9u9",
							},
						},
					},
				},
			},
			want: &types.BlobInfo{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/status.d/base",
						Packages: []types.Package{
							{
								Name:    "base-files",
								Version: "9.9+deb9u9",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dpkgLicenseHook := dpkgLicensePostHandler{}
			a := &analyzer.AnalysisResult{}
			err := dpkgLicenseHook.Handle(context.Background(), a, tt.blob)
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.blob)
		})
	}
}
