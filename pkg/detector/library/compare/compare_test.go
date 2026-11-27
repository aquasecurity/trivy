package compare_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

func TestGenericComparer_IsVulnerable(t *testing.T) {
	type args struct {
		ver      string
		advisory types.Advisory
	}
	tests := []struct {
		name               string
		buildMetadataOrder version.BuildMetadataOrder
		args               args
		want               bool
	}{
		{
			name: "happy path",
			args: args{
				ver: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<=1.0"},
					PatchedVersions:    []string{">=1.1"},
				},
			},
		},
		{
			name: "no patch",
			args: args{
				ver: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<=99.999.99999"},
					PatchedVersions:    []string{"<0.0.0"},
				},
			},
			want: true,
		},
		{
			name: "pre-release",
			args: args{
				ver: "1.2.2-alpha",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<=1.2.2"},
					PatchedVersions:    []string{">=1.2.2"},
				},
			},
			want: true,
		},
		{
			name: "multiple constraints",
			args: args{
				ver: "2.0.0",
				advisory: types.Advisory{
					VulnerableVersions: []string{">=1.7.0 <1.7.16", ">=1.8.0 <1.8.8", ">=2.0.0 <2.0.8", ">=3.0.0-beta.1 <3.0.0-beta.7"},
					PatchedVersions:    []string{">=3.0.0-beta.7", ">=2.0.8 <3.0.0-beta.1", ">=1.8.8 <2.0.0", ">=1.7.16 <1.8.0"},
				},
			},
			want: true,
		},
		{
			name: "invalid version",
			args: args{
				ver: "1.2..4",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<1.0.0"},
				},
			},
			want: false,
		},
		{
			name: "improper constraint",
			args: args{
				ver: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{"*"},
					PatchedVersions:    nil,
				},
			},
			want: false,
		},
		{
			name: "empty patched version",
			args: args{
				ver: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<=99.999.99999"},
					PatchedVersions:    []string{""},
				},
			},
			want: true,
		},
		{
			name: "empty vulnerable & patched version",
			args: args{
				ver: "1.2.3",
				advisory: types.Advisory{
					VulnerableVersions: []string{""},
					PatchedVersions:    []string{""},
				},
			},
			want: true,
		},
		{
			name: "BuildMetadataOrder unset: build metadata ignored",
			args: args{
				ver: "8.0.0+echo.1",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<8.0.0+echo.2"},
					PatchedVersions:    []string{"8.0.0+echo.2"},
				},
			},
			want: false,
		},
		{
			name:               "BuildMetadataOrderNodeSemver: build below the patched build",
			buildMetadataOrder: version.BuildMetadataOrderNodeSemver,
			args: args{
				ver: "8.0.0+echo.1",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<8.0.0+echo.2"},
					PatchedVersions:    []string{"8.0.0+echo.2"},
				},
			},
			want: true,
		},
		{
			name:               "BuildMetadataOrderNodeSemver: build numbers compare numerically",
			buildMetadataOrder: version.BuildMetadataOrderNodeSemver,
			args: args{
				ver: "8.0.0+echo.2",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<8.0.0+echo.10"},
					PatchedVersions:    []string{"8.0.0+echo.10"},
				},
			},
			want: true,
		},
		{
			name:               "BuildMetadataOrderNodeSemver: Echo patched version does not suppress release",
			buildMetadataOrder: version.BuildMetadataOrderNodeSemver,
			args: args{
				ver: "8.0.0",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<8.0.5"},
					PatchedVersions:    []string{"8.0.0+echo.1"},
				},
			},
			want: true,
		},
		{
			name:               "BuildMetadataOrderNodeSemver: exact Echo patched version is suppressed",
			buildMetadataOrder: version.BuildMetadataOrderNodeSemver,
			args: args{
				ver: "8.0.0+echo.1",
				advisory: types.Advisory{
					VulnerableVersions: []string{"<8.0.5"},
					PatchedVersions:    []string{"8.0.0+echo.1"},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := compare.GenericComparer{}
			if tt.buildMetadataOrder != 0 {
				v = compare.NewGenericComparer(compare.WithBuildMetadata(tt.buildMetadataOrder))
			}
			got := v.IsVulnerable(tt.args.ver, tt.args.advisory)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGenericComparer_IsVulnerable_DoesNotMutateInputSlices(t *testing.T) {
	vuln := make([]string, 1, 4)
	vuln[0] = "<2.0.0"
	vulnBacking := vuln[:cap(vuln)]
	vulnBacking[1] = "sentinel-vuln"

	patched := make([]string, 1, 4)
	patched[0] = ">=2.0.0"
	patchedBacking := patched[:cap(patched)]
	patchedBacking[1] = "sentinel-patched"

	advisory := types.Advisory{
		VulnerableVersions: vuln,
		PatchedVersions:    patched,
		UnaffectedVersions: []string{"=0.5.0"},
	}

	v := compare.GenericComparer{}
	assert.True(t, v.IsVulnerable("1.0.0", advisory))
	assert.False(t, v.IsVulnerable("2.0.0", advisory))
	assert.False(t, v.IsVulnerable("0.5.0", advisory))

	assert.Equal(t, []string{"<2.0.0", "sentinel-vuln", "", ""}, vulnBacking)
	assert.Equal(t, []string{">=2.0.0", "sentinel-patched", "", ""}, patchedBacking)
}

func TestGenericComparer_IsVulnerable_Concurrent(t *testing.T) {
	vuln := make([]string, 1, 4)
	vuln[0] = "<2.0.0"
	patched := make([]string, 1, 4)
	patched[0] = ">=2.0.0"
	unaffected := make([]string, 1, 4)
	unaffected[0] = "=0.5.0"

	advisory := types.Advisory{
		VulnerableVersions: vuln,
		PatchedVersions:    patched,
		UnaffectedVersions: unaffected,
	}

	v := compare.GenericComparer{}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 100 {
				assert.True(t, v.IsVulnerable("1.0.0", advisory))
				assert.False(t, v.IsVulnerable("2.0.0", advisory))
				assert.False(t, v.IsVulnerable("0.5.0", advisory))
			}
		})
	}
	wg.Wait()
}
