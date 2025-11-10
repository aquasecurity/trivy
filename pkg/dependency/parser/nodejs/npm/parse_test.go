package npm

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
	}{
		{
			name:     "lock version v1",
			file:     "testdata/package-lock_v1.json",
			want:     npmV1Pkgs,
			wantDeps: npmDeps,
		},
		{
			name:     "lock version v2",
			file:     "testdata/package-lock_v2.json",
			want:     npmV2Pkgs,
			wantDeps: npmDeps,
		},
		{
			name:     "lock version v3",
			file:     "testdata/package-lock_v3.json",
			want:     npmV2Pkgs,
			wantDeps: npmDeps,
		},
		{
			name:     "lock version v3 with workspace",
			file:     "testdata/package-lock_v3_with_workspace.json",
			want:     npmV3WithWorkspacePkgs,
			wantDeps: npmV3WithWorkspaceDeps,
		},
		{
			name:     "lock version v3 with workspace as object",
			file:     "testdata/package-lock_v3_with_workspace_as_object.json",
			want:     npmV3WithWorkspaceAsObjectPkgs,
			wantDeps: nil,
		},
		{
			name:     "lock version v3 with peer dependencies",
			file:     "testdata/package-lock_v3_with_peer.json",
			want:     npmV3WithPeerDependenciesPkgs,
			wantDeps: npmV3WithPeerDependenciesDeps,
		},
		{
			name:     "lock file v3 contains same dev and non-dev dependencies",
			file:     "testdata/package-lock_v3_with-same-dev-and-non-dev.json",
			want:     npmV3WithSameDevAndNonDevPkgs,
			wantDeps: npmV3WithSameDevAndNonDevDeps,
		},
		{
			name:     "lock version v3 with workspace and without direct deps field",
			file:     "testdata/package-lock_v3_without_root_deps_field.json",
			want:     npmV3WithoutRootDepsField,
			wantDeps: npmV3WithoutRootDepsFieldDeps,
		},
		{
			name:     "lock version v3 with broken link",
			file:     "testdata/package-lock_v3_broken_link.json",
			want:     nil,
			wantDeps: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, deps, err := NewParser().Parse(t.Context(), f)
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
			if tt.wantDeps != nil {
				assert.Equal(t, tt.wantDeps, deps)
			}
		})
	}
}

func TestPkgNameFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{
			path:     "node_modules/package-name",
			expected: "package-name",
		},
		{
			path:     "node_modules/@package-namespace/package-name",
			expected: "@package-namespace/package-name",
		},
		{
			path:     "node_modules/package-name/node_modules/sub-sub-package",
			expected: "sub-sub-package",
		},
		{
			path:     "no/node/modules/dir",
			expected: "no/node/modules/dir",
		},
		{
			path:     "node_modules",
			expected: "",
		},
		{
			path:     "node_modules/",
			expected: "",
		},
	}

	parser := NewParser()
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			path := parser.pkgNameFromPath(test.path)
			assert.Equal(t, test.expected, path)
		})
	}
}
