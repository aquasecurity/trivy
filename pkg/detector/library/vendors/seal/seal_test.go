package seal

import (
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
)

func TestSealSecurity_Match(t *testing.T) {
	tests := []struct {
		name    string
		eco     ecosystem.Type
		pkgName string
		pkgVer  string
		want    bool
	}{
		// Maven - name prefix seal.sp$X.$groupId:$artifactId
		{
			name:    "maven seal package",
			eco:     ecosystem.Maven,
			pkgName: "seal.sp1.org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622",
			want:    true,
		},
		{
			name:    "maven seal package with sp2",
			eco:     ecosystem.Maven,
			pkgName: "seal.sp2.org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622",
			want:    true,
		},
		{
			name:    "maven non-seal package",
			eco:     ecosystem.Maven,
			pkgName: "org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622",
			want:    false,
		},
		// npm - name prefix @seal-security/
		{
			name:    "npm seal package",
			eco:     ecosystem.Npm,
			pkgName: "@seal-security/ejs",
			pkgVer:  "3.1.8-sp1",
			want:    true,
		},
		{
			name:    "npm seal package with seal- prefix in name",
			eco:     ecosystem.Npm,
			pkgName: "@seal-security/seal-ejs",
			pkgVer:  "3.1.8-sp1",
			want:    true,
		},
		{
			name:    "npm non-seal package",
			eco:     ecosystem.Npm,
			pkgName: "ejs",
			pkgVer:  "3.1.8-sp1",
			want:    false,
		},
		// Python - name prefix seal-
		{
			name:    "python seal package",
			eco:     ecosystem.Pip,
			pkgName: "seal-django",
			pkgVer:  "4.2.8+sp1",
			want:    true,
		},
		{
			name:    "python non-seal package",
			eco:     ecosystem.Pip,
			pkgName: "django",
			pkgVer:  "4.2.8+sp1",
			want:    false,
		},
		// Go - name prefix sealsecurity.io/
		{
			name:    "go seal package",
			eco:     ecosystem.Go,
			pkgName: "sealsecurity.io/github.com/Masterminds/goutils",
			pkgVer:  "v1.1.1-sp1",
			want:    true,
		},
		{
			name:    "go non-seal package",
			eco:     ecosystem.Go,
			pkgName: "github.com/Masterminds/goutils",
			pkgVer:  "v1.1.1-sp1",
			want:    false,
		},
		// Unsupported ecosystem
		{
			name:    "rubygems package is not supported",
			eco:     ecosystem.RubyGems,
			pkgName: "activesupport",
			pkgVer:  "7.0.0",
			want:    false,
		},
		// Edge cases
		{
			name:    "empty version",
			eco:     ecosystem.Pip,
			pkgName: "seal-requests",
			pkgVer:  "",
			want:    true,
		},
		{
			name:    "empty package name",
			eco:     ecosystem.Pip,
			pkgName: "",
			pkgVer:  "1.0.0",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := SealSecurity{}
			got := s.Match(tt.eco, tt.pkgName, tt.pkgVer)
			if got != tt.want {
				t.Errorf("SealSecurity.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}
