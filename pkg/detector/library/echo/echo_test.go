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
			name:    "pip package with +echo.1 suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+echo.1",
			want:    library.Matched,
		},
		{
			name:    "pip package with +echo.999 suffix",
			eco:     ecosystem.Pip,
			pkgName: "django",
			pkgVer:  "4.2.8+echo.999",
			want:    library.Matched,
		},
		{
			name:    "pip package with +echo.2 suffix",
			eco:     ecosystem.Pip,
			pkgName: "flask",
			pkgVer:  "3.0.0+echo.2",
			want:    library.Matched,
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
			name:    "npm package is not supported",
			eco:     ecosystem.Npm,
			pkgName: "ejs",
			pkgVer:  "3.1.8+echo.1",
			want:    library.NoMatch,
		},
		{
			name:    "go package is not supported",
			eco:     ecosystem.Go,
			pkgName: "golang.org/x/crypto",
			pkgVer:  "0.26.0+echo.1",
			want:    library.NoMatch,
		},
		{
			name:    "maven package is not supported",
			eco:     ecosystem.Maven,
			pkgName: "org.apache.logging.log4j:log4j-core",
			pkgVer:  "2.13.3+echo.1",
			want:    library.NoMatch,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := echoSupplier{}
			got := v.Match(tt.eco, tt.pkgName, tt.pkgVer)
			require.Equal(t, tt.want, got)
		})
	}
}
