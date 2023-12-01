package ospkgid

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

func TestOverwritePkgIdentifiers(t *testing.T) {
	testCases := []struct {
		name     string
		pkgInfos []types.PackageInfo
		os       types.OS
		want     []types.PackageInfo
	}{
		{
			name: "no os family",
			pkgInfos: []types.PackageInfo{{
				Packages: []types.Package{{
					Name:    "test",
					Version: "0.1.0",
					Arch:    "amd64",
					Identifier: types.PkgIdentifier{
						PURL: "pkg:dpkg/test@0.1.0?arch=amd64",
					},
				}},
			}},
			os: types.OS{},
			want: []types.PackageInfo{{
				Packages: []types.Package{{
					Name:    "test",
					Version: "0.1.0",
					Arch:    "amd64",
					Identifier: types.PkgIdentifier{
						PURL: "pkg:dpkg/test@0.1.0?arch=amd64",
					},
				}},
			}},
		},
		{
			name: "success",
			pkgInfos: []types.PackageInfo{{
				Packages: []types.Package{{
					Name:    "test",
					Version: "0.1.0",
					Arch:    "amd64",
					Identifier: types.PkgIdentifier{
						PURL: "pkg:dpkg/test@0.1.0?arch=amd64",
					},
				}},
			}},
			os: types.OS{
				Family: types.Debian,
				Name:   "10.2",
			},
			want: []types.PackageInfo{{
				Packages: []types.Package{{
					Name:    "test",
					Version: "0.1.0",
					Arch:    "amd64",
					Identifier: types.PkgIdentifier{
						PURL: "pkg:deb/debian/test@0.1.0?arch=amd64&distro=debian-10.2",
					},
				}},
			}},
		},
	}
	t.Parallel()
	for _, tc := range testCases {
		test := tc
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()
			pkgIdentifier := overwritePkgIdentifiers(test.pkgInfos, test.os)
			assert.Equal(tt, test.want, pkgIdentifier, test.name)
		})
	}
}
