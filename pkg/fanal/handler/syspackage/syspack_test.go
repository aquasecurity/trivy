package syspackage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_systemPackagesPostHandler_Handle(t *testing.T) {
	tests := []struct {
		name string
		blob *types.BlobInfo
		want *types.BlobInfo
	}{
		{
			name: "happy path",
			blob: &types.BlobInfo{
				OS: types.OS{
					Family: types.CentOS,
					Name:   "7.9.2009",
				},
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/rpm/Packages",
						Packages: types.Packages{
							{
								Name:    "python",
								Version: "2.7.5",
								Release: "89.el7",
							},
							{
								Name:    "python-libs",
								Version: "2.7.5",
								Release: "89.el7",
							},
						},
					},
				},
			},
			want: &types.BlobInfo{
				OS: types.OS{
					Family: types.CentOS,
					Name:   "7.9.2009",
				},
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/rpm/Packages",
						Packages: types.Packages{
							{
								Name:    "python",
								Version: "2.7.5",
								Release: "89.el7",
								Identifier: types.PkgIdentifier{
									PURL: "pkg:rpm/centos/python@2.7.5-89.el7?distro=centos-7.9.2009",
								},
							},
							{
								Name:    "python-libs",
								Version: "2.7.5",
								Release: "89.el7",
								Identifier: types.PkgIdentifier{
									PURL: "pkg:rpm/centos/python-libs@2.7.5-89.el7?distro=centos-7.9.2009",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := systemPackagesPostHandler{}
			err := h.Handle(context.TODO(), nil, tt.blob)
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.blob)
		})
	}
}
