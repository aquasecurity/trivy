package gomod

import (
	"context"
	"testing"

	"golang.org/x/exp/slices"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_gomodMergeHook_Hook(t *testing.T) {
	tests := []struct {
		name string
		blob *types.BlobInfo
		want *types.BlobInfo
	}{
		{
			name: "Go 1.17",
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.Pipenv,
						FilePath: "app/Pipfile.lock",
						Libraries: []types.Package{
							{
								Name:    "django",
								Version: "3.1.2",
							},
						},
					},
					{
						Type:     types.GoModule,
						FilePath: "/app/go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "v0.0.0-20220412145205-d0501f906d90",
							},
							{
								Name:    "github.com/aws/aws-sdk-go",
								Version: "v1.43.31",
							},
							{
								Name:     "gopkg.in/yaml.v2",
								Version:  "v2.4.0",
								Indirect: true,
							},
						},
					},
					{
						Type:     types.GoModule,
						FilePath: "/app/go.sum",
						Libraries: []types.Package{
							{
								Name:    "modernc.org/libc",
								Version: "v0.0.0-20220412145205-d0501f906d90",
							},
						},
					},
				},
			},
			want: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.Pipenv,
						FilePath: "app/Pipfile.lock",
						Libraries: []types.Package{
							{
								Name:    "django",
								Version: "3.1.2",
							},
						},
					},
					{
						Type:     types.GoModule,
						FilePath: "/app/go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "v0.0.0-20220412145205-d0501f906d90",
							},
							{
								Name:    "github.com/aws/aws-sdk-go",
								Version: "v1.43.31",
							},
							{
								Name:     "gopkg.in/yaml.v2",
								Version:  "v2.4.0",
								Indirect: true,
							},
						},
					},
				},
			},
		},
		{
			name: "Go 1.16",
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "app/go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "v0.0.0-20220412145205-d0501f906d90",
							},
							{
								Name:    "github.com/aws/aws-sdk-go",
								Version: "v1.43.31",
							},
						},
					},
					{
						Type:     types.GoModule,
						FilePath: "app/go.sum",
						Libraries: []types.Package{
							{
								Name:    "modernc.org/libc",
								Version: "v0.0.0-20220412145205-d0501f906d90",
							},
							{
								Name:    "github.com/aws/aws-sdk-go",
								Version: "v1.45.0",
							},
						},
					},
				},
			},
			want: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "app/go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "v0.0.0-20220412145205-d0501f906d90",
							},
							{
								Name:    "github.com/aws/aws-sdk-go",
								Version: "v1.43.31",
							},
							{
								Name:     "modernc.org/libc",
								Version:  "v0.0.0-20220412145205-d0501f906d90",
								Indirect: true,
							},
						},
					},
				},
			},
		},
		{
			name: "Go 1.16 and go.sum is not found",
			blob: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "app/go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "v0.0.0-20220412145205-d0501f906d90",
							},
							{
								Name:    "github.com/aws/aws-sdk-go",
								Version: "v1.43.31",
							},
						},
					},
				},
			},
			want: &types.BlobInfo{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "app/go.mod",
						Libraries: []types.Package{
							{
								Name:    "github.com/aquasecurity/go-dep-parser",
								Version: "v0.0.0-20220412145205-d0501f906d90",
							},
							{
								Name:    "github.com/aws/aws-sdk-go",
								Version: "v1.43.31",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := gomodMergeHook{}
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
