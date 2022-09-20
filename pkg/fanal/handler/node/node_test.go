package node

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"
)

func Test_Handle(t *testing.T) {
	tests := []struct {
		name string
		blob *types.BlobInfo
		want *types.BlobInfo
	}{
		{
			name: "happy path",
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.Npm,
						FilePath: "package-lock.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
							},
						},
					},
					{
						Type:     types.Npm,
						FilePath: "app/package-lock.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
							},
						},
					},
					{
						Type:     types.NodePkg,
						FilePath: "package.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
								Licenses: []string{
									"Apache-1.0",
								},
							},
						},
					},
					{
						Type:     types.NodePkg,
						FilePath: "node_modules/@colors/colors/package.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
								Licenses: []string{
									"Apache-2.0",
								},
							},
						},
					},
					{
						Type:     types.NodePkg,
						FilePath: "app/node_modules/@colors/colors/package.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
								Licenses: []string{
									"Apache-3.0",
								},
							},
						},
					},
				},
			},
			want: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.Npm,
						FilePath: "package-lock.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
								Licenses: []string{
									"Apache-2.0",
								},
							},
						},
					},
					{
						Type:     types.Npm,
						FilePath: "app/package-lock.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
								Licenses: []string{
									"Apache-3.0",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path. No package.json files",
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.Npm,
						FilePath: "package-lock.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
							},
						},
					},
					{
						Type:     types.Npm,
						FilePath: "app/package-lock.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
							},
						},
					},
				},
			},
			want: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.Npm,
						FilePath: "package-lock.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
							},
						},
					},
					{
						Type:     types.Npm,
						FilePath: "app/package-lock.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
							},
						},
					},
				},
			},
		},
		{
			name: "happy path. No package-lock.json files",
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.NodePkg,
						FilePath: "node_modules/@colors/colors/package.json",
						Libraries: []types.Package{
							{
								Name:    "@colors/colors",
								Version: "1.5.0",
								Licenses: []string{
									"Apache-2.0",
								},
							},
						},
					},
				},
			},
			want: &types.BlobInfo{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := nodeLicensesMergeHandler{}
			err := h.Handle(context.Background(), nil, tt.blob)
			require.NoError(t, err)

			for i := range tt.blob.Applications {
				slices.SortFunc(tt.blob.Applications[i].Libraries, func(a, b types.Package) bool {
					return a.Name < b.Name
				})
			}
			assert.Equal(t, tt.want, tt.blob)
		})
	}
}
