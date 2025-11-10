package core_deps

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		file     string // Test input file
		want     []ftypes.Package
		wantDeps []ftypes.Dependency
		wantErr  string
	}{
		{
			name: "happy path",
			file: "testdata/happy.deps.json",
			want: []ftypes.Package{
				{
					ID:           "ExampleApp1/1.0.0",
					Name:         "ExampleApp1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
					Locations: []ftypes.Location{
						{
							StartLine: 28,
							EndLine:   32,
						},
					},
				},
				{
					ID:           "Newtonsoft.Json/13.0.1",
					Name:         "Newtonsoft.Json",
					Version:      "13.0.1",
					Relationship: ftypes.RelationshipDirect,
					Locations: []ftypes.Location{
						{
							StartLine: 33,
							EndLine:   39,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID:        "ExampleApp1/1.0.0",
					DependsOn: []string{"Newtonsoft.Json/13.0.1"},
				},
			},
		},
		{
			name: "happy path with skipped libs",
			file: "testdata/without-runtime.deps.json",
			want: []ftypes.Package{
				{
					ID:           "hello2/1.0.0",
					Name:         "hello2",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
					Locations: []ftypes.Location{
						{
							StartLine: 61,
							EndLine:   65,
						},
					},
				},
				{
					ID:           "JsonDiffPatch/2.0.61",
					Name:         "JsonDiffPatch",
					Version:      "2.0.61",
					Relationship: ftypes.RelationshipDirect,
					Locations: []ftypes.Location{
						{
							StartLine: 66,
							EndLine:   72,
						},
					},
				},
				{
					ID:           "Libuv/1.9.1",
					Name:         "Libuv",
					Version:      "1.9.1",
					Relationship: ftypes.RelationshipIndirect,
					Locations: []ftypes.Location{
						{
							StartLine: 73,
							EndLine:   79,
						},
					},
				},
				{
					ID:           "System.Collections.Immutable/1.3.0",
					Name:         "System.Collections.Immutable",
					Version:      "1.3.0",
					Relationship: ftypes.RelationshipIndirect,
					Locations: []ftypes.Location{
						{
							StartLine: 101,
							EndLine:   107,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID:        "hello2/1.0.0",
					DependsOn: []string{"JsonDiffPatch/2.0.61"},
				},
			},
		},
		{
			name:     "happy path without libs",
			file:     "testdata/no-libraries.deps.json",
			want:     nil,
			wantDeps: nil,
		},
		{
			name: "target libs not found",
			file: "testdata/missing-target.deps.json",
			want: []ftypes.Package{
				{
					ID:           "ExampleApp1/1.0.0",
					Name:         "ExampleApp1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
					Locations: []ftypes.Location{
						{
							StartLine: 28,
							EndLine:   32,
						},
					},
				},
				{
					ID:      "Newtonsoft.Json/13.0.1",
					Name:    "Newtonsoft.Json",
					Version: "13.0.1",
					Locations: []ftypes.Location{
						{
							StartLine: 33,
							EndLine:   39,
						},
					},
				},
			},
			wantDeps: nil,
		},
		{
			name:    "sad path",
			file:    "testdata/invalid.deps.json",
			wantErr: "failed to decode .deps.json file: jsontext: unexpected EOF within",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, gotDeps, err := NewParser().Parse(t.Context(), f)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}
