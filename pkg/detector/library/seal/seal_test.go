package seal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library"
)

func TestSealSecurity_Match(t *testing.T) {
	tests := []struct {
		name    string
		eco     ecosystem.Type
		pkgName string
		pkgVer  string
		want    library.MatchResult
	}{
		// Maven - renamed name prefix seal.sp$X.$groupId:$artifactId
		{
			name:    "maven seal package",
			eco:     ecosystem.Maven,
			pkgName: "seal.sp1.org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622",
			want:    library.Matched,
		},
		{
			name:    "maven seal package with sp2",
			eco:     ecosystem.Maven,
			pkgName: "seal.sp2.org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622",
			want:    library.Matched,
		},
		{
			name:    "maven non-seal package",
			eco:     ecosystem.Maven,
			pkgName: "org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622",
			want:    library.NoMatch,
		},
		{
			name:    "maven non-seal package with seal.sp prefix but no digit",
			eco:     ecosystem.Maven,
			pkgName: "seal.space.something:artifact",
			pkgVer:  "1.0.0",
			want:    library.NoMatch,
		},
		// Maven - no-prefix name detected by "+spN" version suffix
		{
			name:    "maven seal package with no-prefix name and version suffix",
			eco:     ecosystem.Maven,
			pkgName: "org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622+sp1",
			want:    library.Matched,
		},
		// npm - renamed name prefix @seal-security/
		{
			name:    "npm seal package",
			eco:     ecosystem.Npm,
			pkgName: "@seal-security/ejs",
			pkgVer:  "3.1.8-sp1",
			want:    library.Matched,
		},
		{
			name:    "npm seal package with seal- prefix in name",
			eco:     ecosystem.Npm,
			pkgName: "@seal-security/seal-ejs",
			pkgVer:  "3.1.8-sp1",
			want:    library.Matched,
		},
		{
			name:    "npm non-seal package without version suffix",
			eco:     ecosystem.Npm,
			pkgName: "ejs",
			pkgVer:  "3.1.8",
			want:    library.NoMatch,
		},
		// npm - no-prefix name with "-spN" suffix is a candidate (verified against DB)
		{
			name:    "npm seal package with no-prefix name and version suffix",
			eco:     ecosystem.Npm,
			pkgName: "ejs",
			pkgVer:  "3.1.8-sp1",
			want:    library.Candidate,
		},
		// Python - renamed name prefix seal-
		{
			name:    "python seal package",
			eco:     ecosystem.Pip,
			pkgName: "seal-django",
			pkgVer:  "4.2.8+sp1",
			want:    library.Matched,
		},
		{
			name:    "python non-seal package without version suffix",
			eco:     ecosystem.Pip,
			pkgName: "django",
			pkgVer:  "4.2.8",
			want:    library.NoMatch,
		},
		// Python - no-prefix name detected by "+spN" version suffix
		{
			name:    "python seal package with no-prefix name and version suffix",
			eco:     ecosystem.Pip,
			pkgName: "django",
			pkgVer:  "4.2.8+sp1",
			want:    library.Matched,
		},
		// Go - renamed name prefix sealsecurity.io/
		{
			name:    "go seal package",
			eco:     ecosystem.Go,
			pkgName: "sealsecurity.io/github.com/Masterminds/goutils",
			pkgVer:  "v1.1.1-sp1",
			want:    library.Matched,
		},
		{
			name:    "go non-seal package without version suffix",
			eco:     ecosystem.Go,
			pkgName: "github.com/Masterminds/goutils",
			pkgVer:  "v1.1.1",
			want:    library.NoMatch,
		},
		// Go - no-prefix name with "-spN" suffix is a candidate (verified against DB)
		{
			name:    "go seal package with no-prefix name and version suffix",
			eco:     ecosystem.Go,
			pkgName: "github.com/Masterminds/goutils",
			pkgVer:  "v1.1.1-sp1",
			want:    library.Candidate,
		},
		// Ruby - renamed name prefix seal-
		{
			name:    "ruby seal package",
			eco:     ecosystem.RubyGems,
			pkgName: "seal-rack",
			pkgVer:  "2.0.7.0.1.sp1",
			want:    library.Matched,
		},
		{
			name:    "ruby non-seal package without version suffix",
			eco:     ecosystem.RubyGems,
			pkgName: "rack",
			pkgVer:  "2.0.7",
			want:    library.NoMatch,
		},
		// Ruby - no-prefix name with ".spN" suffix is a candidate (verified against DB)
		{
			name:    "ruby seal package with no-prefix name and version suffix",
			eco:     ecosystem.RubyGems,
			pkgName: "rack",
			pkgVer:  "2.0.7.0.1.sp1",
			want:    library.Candidate,
		},
		// Unsupported ecosystem
		{
			name:    "erlang package is not supported",
			eco:     ecosystem.Erlang,
			pkgName: "seal-cowboy",
			pkgVer:  "2.9.0",
			want:    library.NoMatch,
		},
		// Edge cases
		{
			name:    "empty version",
			eco:     ecosystem.Pip,
			pkgName: "seal-requests",
			pkgVer:  "",
			want:    library.Matched,
		},
		{
			name:    "empty package name",
			eco:     ecosystem.Pip,
			pkgName: "",
			pkgVer:  "1.0.0",
			want:    library.NoMatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := sealSecurity{}
			got := s.Match(tt.eco, tt.pkgName, tt.pkgVer)
			require.Equal(t, tt.want, got)
		})
	}
}
