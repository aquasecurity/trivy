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
			// Self-contained deployments bundle the runtime into the app's deps.json as
			// `runtimepack.<name>` libraries. They must be reported with the prefix stripped
			// so the name matches the advisory DB (Microsoft.NETCore.App.Runtime.<rid>).
			name: "self-contained with bundled runtime",
			file: "testdata/self-contained.deps.json",
			want: []ftypes.Package{
				{
					ID:           "ExampleApp1/1.0.0",
					Name:         "ExampleApp1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
					Locations: []ftypes.Location{
						{
							StartLine: 44,
							EndLine:   48,
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
							StartLine: 49,
							EndLine:   55,
						},
					},
				},
				{
					ID:           "Microsoft.AspNetCore.App.Runtime.linux-x64/8.0.0",
					Name:         "Microsoft.AspNetCore.App.Runtime.linux-x64",
					Version:      "8.0.0",
					Relationship: ftypes.RelationshipIndirect,
					Locations: []ftypes.Location{
						{
							StartLine: 61,
							EndLine:   65,
						},
					},
				},
				{
					ID:           "Microsoft.NETCore.App.Runtime.linux-x64/8.0.0",
					Name:         "Microsoft.NETCore.App.Runtime.linux-x64",
					Version:      "8.0.0",
					Relationship: ftypes.RelationshipIndirect,
					Locations: []ftypes.Location{
						{
							StartLine: 56,
							EndLine:   60,
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
			// Only `runtimepack`-typed libraries get the `runtimepack.` prefix stripped.
			// A real `package` that ships a native DLL keeps its name, and a (contrived)
			// `package` whose name merely starts with "runtimepack." must NOT be rewritten.
			name: "runtimepack prefix is stripped only for runtimepack-typed libs",
			file: "testdata/runtimepack-edge.deps.json",
			want: []ftypes.Package{
				{
					ID:           "ExampleApp1/1.0.0",
					Name:         "ExampleApp1",
					Version:      "1.0.0",
					Relationship: ftypes.RelationshipRoot,
					Locations: []ftypes.Location{
						{
							StartLine: 41,
							EndLine:   45,
						},
					},
				},
				{
					ID:           "SQLitePCLRaw.lib.e_sqlite3/2.1.6",
					Name:         "SQLitePCLRaw.lib.e_sqlite3",
					Version:      "2.1.6",
					Relationship: ftypes.RelationshipDirect,
					Locations: []ftypes.Location{
						{
							StartLine: 46,
							EndLine:   52,
						},
					},
				},
				{
					ID:           "Microsoft.NETCore.App.Runtime.linux-x64/8.0.0",
					Name:         "Microsoft.NETCore.App.Runtime.linux-x64",
					Version:      "8.0.0",
					Relationship: ftypes.RelationshipIndirect,
					Locations: []ftypes.Location{
						{
							StartLine: 60,
							EndLine:   64,
						},
					},
				},
				{
					ID:           "runtimepack.Acme.Custom.Pack/4.5.6",
					Name:         "runtimepack.Acme.Custom.Pack",
					Version:      "4.5.6",
					Relationship: ftypes.RelationshipIndirect,
					Locations: []ftypes.Location{
						{
							StartLine: 53,
							EndLine:   59,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID:        "ExampleApp1/1.0.0",
					DependsOn: []string{"SQLitePCLRaw.lib.e_sqlite3/2.1.6"},
				},
			},
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
