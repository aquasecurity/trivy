package echo

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
)

func TestEchoVendor_Match(t *testing.T) {
	tests := []struct {
		name    string
		eco     ecosystem.Type
		pkgName string
		pkgVer  string
		want    bool
	}{
		{
			name:    "pip package with +echo.1 suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+echo.1",
			want:    true,
		},
		{
			name:    "pip package with +echo.999 suffix",
			eco:     ecosystem.Pip,
			pkgName: "django",
			pkgVer:  "4.2.8+echo.999",
			want:    true,
		},
		{
			name:    "pip package with +echo.2 suffix",
			eco:     ecosystem.Pip,
			pkgName: "flask",
			pkgVer:  "3.0.0+echo.2",
			want:    true,
		},
		{
			name:    "pip package without echo suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2",
			want:    false,
		},
		{
			name:    "pip package with different local suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2+local.1",
			want:    false,
		},
		{
			name:    "npm package is not supported",
			eco:     ecosystem.Npm,
			pkgName: "ejs",
			pkgVer:  "3.1.8+echo.1",
			want:    false,
		},
		{
			name:    "go package is not supported",
			eco:     ecosystem.Go,
			pkgName: "golang.org/x/crypto",
			pkgVer:  "0.26.0+echo.1",
			want:    false,
		},
		{
			name:    "maven package is not supported",
			eco:     ecosystem.Maven,
			pkgName: "org.apache.logging.log4j:log4j-core",
			pkgVer:  "2.13.3+echo.1",
			want:    false,
		},
		{
			name:    "empty version",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "",
			want:    false,
		},
		{
			name:    "version containing echo but not as local segment",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.14.2-echo.1",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := echoVendor{}
			got := v.Match(tt.eco, tt.pkgName, tt.pkgVer)
			require.Equal(t, tt.want, got)
		})
	}
}
