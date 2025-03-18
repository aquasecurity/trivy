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
		name           string
		file           string // Test input file
		includeDevDeps bool
		want           []ftypes.Package
		wantDeps       []ftypes.Dependency
	}{
		{
			name:           "lock version v1",
			file:           "testdata/package-lock_v1.json",
			includeDevDeps: true,
			want:           npmV1Pkgs,
			wantDeps:       npmDeps,
		},
		{
			name:           "lock version v1. Exclude Dev deps",
			file:           "testdata/package-lock_v1.json",
			includeDevDeps: false,
			want:           npmV1PkgsExcludeDev,
			wantDeps:       npmDepsExcludeDev,
		},
		{
			name:           "lock version v2",
			file:           "testdata/package-lock_v2.json",
			includeDevDeps: true,
			want:           npmV2Pkgs,
			wantDeps:       npmDeps,
		},
		{
			name:           "lock version v3",
			file:           "testdata/package-lock_v3.json",
			includeDevDeps: true,
			want:           npmV2Pkgs,
			wantDeps:       npmDeps,
		},
		{
			name:           "lock version v3. Exclude Dev deps",
			file:           "testdata/package-lock_v3.json",
			includeDevDeps: false,
			want:           npmV2PkgsExcludeDev,
			wantDeps:       npmV2DepsExcludeDev,
		},
		{
			name:           "lock version v3 with workspace",
			file:           "testdata/package-lock_v3_with_workspace.json",
			includeDevDeps: true,
			want:           npmV3WithWorkspacePkgs,
			wantDeps:       npmV3WithWorkspaceDeps,
		},
		{
			name:     "lock version v3 with peer dependencies",
			file:     "testdata/package-lock_v3_with_peer.json",
			want:     npmV3WithPeerDependenciesPkgs,
			includeDevDeps: true,
			wantDeps: npmV3WithPeerDependenciesDeps,
		},
		{
			name:     "lock file v3 contains same dev and non-dev dependencies",
			file:     "testdata/package-lock_v3_with-same-dev-and-non-dev.json",
			includeDevDeps: true,
			want:     npmV3WithSameDevAndNonDevPkgs,
			wantDeps: npmV3WithSameDevAndNonDevDeps,
		},
		{
			name:           "lock file v3 contains same dev and non-dev dependencies. Exclude Dev deps",
			file:           "testdata/package-lock_v3_with-same-dev-and-non-dev.json",
			includeDevDeps: false,
			want:           npmV3WithSameDevAndNonDevPkgsExcludeDev,
			wantDeps:       nil,
		},
		{
			name:           "lock version v3 with workspace and without direct deps field",
			file:           "testdata/package-lock_v3_without_root_deps_field.json",
			includeDevDeps: true,
			want:           npmV3WithoutRootDepsField,
			wantDeps:       npmV3WithoutRootDepsFieldDeps,
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

			got, deps, err := NewParser(tt.includeDevDeps).Parse(f)
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
			if tt.wantDeps != nil {
				assert.Equal(t, tt.wantDeps, deps)
			}
		})
	}
}
