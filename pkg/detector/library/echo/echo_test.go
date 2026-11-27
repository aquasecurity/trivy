package echo

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library"
)

func TestEchoSupplier_Match(t *testing.T) {
	tests := []struct {
		name    string
		eco     ecosystem.Type
		pkgName string
		pkgVer  string
		want    library.MatchResult
	}{
		{
			name:    "pip package with +echo.N suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+echo.1",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "pip package without echo suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2",
			want:    library.NoMatch,
		},
		{
			name:    "pip package with different local suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+local.1",
			want:    library.NoMatch,
		},
		{
			name:    "npm package with +echo.1 suffix",
			eco:     ecosystem.Npm,
			pkgName: "nanoid",
			pkgVer:  "3.3.6+echo.1",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "nuget package with +echo.1 suffix",
			eco:     ecosystem.NuGet,
			pkgName: "system.security.cryptography.xml",
			pkgVer:  "8.0.0+echo.1",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "go package with +echo.1 suffix",
			eco:     ecosystem.Go,
			pkgName: "golang.org/x/crypto",
			pkgVer:  "v0.26.0+echo.1",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "go package without v prefix",
			eco:     ecosystem.Go,
			pkgName: "golang.org/x/crypto",
			pkgVer:  "0.26.0+echo.1",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "go package with later metadata identifiers",
			eco:     ecosystem.Go,
			pkgName: "golang.org/x/crypto",
			pkgVer:  "v0.26.0+echo.1.extra.1",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "go package with joined Echo revision",
			eco:     ecosystem.Go,
			pkgName: "golang.org/x/crypto",
			pkgVer:  "v0.26.0+echo.1-extra.1",
			want:    library.NoMatch,
		},
		{
			name:    "go package with malformed core version",
			eco:     ecosystem.Go,
			pkgName: "golang.org/x/crypto",
			pkgVer:  "v0.26.0.1+echo.1",
			want:    library.NoMatch,
		},
		{
			name:    "go package with empty trailing metadata identifier",
			eco:     ecosystem.Go,
			pkgName: "golang.org/x/crypto",
			pkgVer:  "v0.26.0+echo.1.",
			want:    library.NoMatch,
		},
		{
			name:    "go package with zero-padded Echo revision",
			eco:     ecosystem.Go,
			pkgName: "golang.org/x/crypto",
			pkgVer:  "v0.26.0+echo.01",
			want:    library.NoMatch,
		},
		{
			name:    "maven package with +echo.1 suffix",
			eco:     ecosystem.Maven,
			pkgName: "org.springframework:spring-core",
			pkgVer:  "6.1.21+echo.1",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "empty version",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "",
			want:    library.NoMatch,
		},
		{
			name:    "version containing echo but not as local segment",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2-echo.1",
			want:    library.NoMatch,
		},
		{
			name:    "pip package with +echo. but no digits",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+echo.",
			want:    library.NoMatch,
		},
		{
			name:    "pip package with +echo. followed by non-digit",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+echo.beta",
			want:    library.NoMatch,
		},
		{
			name:    "pip package with characters after the echo number",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+echo.1foo",
			want:    library.NoMatch,
		},
		{
			name:    "pip package with another segment after the echo number",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+echo.1.2",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "pip package with a named segment after the echo number",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+echo.1.post1",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "pip package with a dash-separated segment after the echo number",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+echo.1-cu118",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "pip package with an underscore-separated segment after the echo number",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+echo.1_cu118",
			want:    library.MatchedWithUpstream,
		},
		{
			name:    "pip package with echo segment not at the start of the local version",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+cu118.echo.1",
			want:    library.NoMatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := echoSupplier{}
			got := e.Match(tt.eco, tt.pkgName, tt.pkgVer)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestEchoSupplier_UpstreamVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Echo revision",
			version: "5.3.39+echo.1",
			want:    "5.3.39",
		},
		{
			name:    "later metadata segments",
			version: "v0.22.0+echo.1.frontier.1",
			want:    "v0.22.0",
		},
		{
			name:    "plain upstream version",
			version: "5.3.39",
			want:    "5.3.39",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, (echoSupplier{}).UpstreamVersion(tt.version))
		})
	}
}
