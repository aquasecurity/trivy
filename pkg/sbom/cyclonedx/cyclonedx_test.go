package cyclonedx

import (
	"sort"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/types"
)

func TestTrivyBOM_Aggregate(t *testing.T) {

	tests := []struct {
		name    string
		libs    []cdx.Component
		want    []types.Application
		wantErr string
	}{
		{
			name: "happy path",
			libs: []cdx.Component{
				{
					BOMRef:     "pkg:composer/pear/pear_exception@v1.0.0",
					PackageURL: "pkg:composer/pear/pear_exception@v1.0.0",
				},
				{
					BOMRef:     "pkg:npm/bootstrap@5.0.2?file_path=app%2Fapp%2Fpackage.json",
					PackageURL: "pkg:npm/bootstrap@5.0.2?file_path=app%2Fapp%2Fpackage.json",
				},
			},
			want: []types.Application{
				{
					Type:     "composer",
					FilePath: "composer",
					Libraries: []types.Package{
						{
							Name:    "pear/pear_exception",
							Version: "v1.0.0",
							Ref:     "pkg:composer/pear/pear_exception@v1.0.0",
						},
					},
				},
				{
					Type:     "node-pkg",
					FilePath: "npm",
					Libraries: []types.Package{
						{
							Name:    "bootstrap",
							Version: "5.0.2",
							Ref:     "pkg:npm/bootstrap@5.0.2?file_path=app%2Fapp%2Fpackage.json",
						},
					},
				},
			},
		},
		{
			name: "sad path invalid component",
			libs: []cdx.Component{
				{
					BOMRef:     "pkg:composer/pear/pear_exception@v1.0.0",
					PackageURL: "invalidpurl",
				},
			},
			wantErr: "failed to parse purl",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := TrivyBOM{}
			got, err := b.Aggregate(tt.libs)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			} else {
				require.NoError(t, err)
			}
			sort.Slice(got, func(i, j int) bool {
				return got[i].FilePath < got[j].FilePath
			})
			assert.Equal(t, tt.want, got)
		})
	}
}
