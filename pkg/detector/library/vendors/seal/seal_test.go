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
		// Maven and Python use +spX suffix
		{
			name:    "python package with +sp suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.28.1+sp1",
			want:    true,
		},
		{
			name:    "python package with +sp suffix multi-digit",
			eco:     ecosystem.Pip,
			pkgName: "django",
			pkgVer:  "4.2.0+sp10",
			want:    true,
		},
		{
			name:    "maven package with +sp suffix",
			eco:     ecosystem.Maven,
			pkgName: "org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622+sp1",
			want:    true,
		},
		// Other ecosystems use -spX suffix
		{
			name:    "node package with -sp suffix",
			eco:     ecosystem.Npm,
			pkgName: "ejs",
			pkgVer:  "3.1.8-sp1",
			want:    true,
		},
		{
			name:    "golang package with -sp suffix",
			eco:     ecosystem.Go,
			pkgName: "github.com/Masterminds/goutils",
			pkgVer:  "v1.1.1-sp1",
			want:    true,
		},
		{
			name:    "golang package with -sp suffix multi-digit",
			eco:     ecosystem.Go,
			pkgName: "github.com/Masterminds/goutils",
			pkgVer:  "v1.1.1-sp10",
			want:    true,
		},
		{
			name:    "rubygems package with -sp suffix",
			eco:     ecosystem.RubyGems,
			pkgName: "activesupport",
			pkgVer:  "7.0.0-sp1",
			want:    true,
		},
		// Maven - also supports package name prefix (without version suffix)
		{
			name:    "maven package with seal.sp prefix (no version suffix)",
			eco:     ecosystem.Maven,
			pkgName: "seal.sp1.org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622",
			want:    true,
		},
		{
			name:    "maven package with seal.sp2 prefix (no version suffix)",
			eco:     ecosystem.Maven,
			pkgName: "seal.sp2.org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622",
			want:    true,
		},
		{
			name:    "maven package without seal.sp prefix and no sp suffix",
			eco:     ecosystem.Maven,
			pkgName: "org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622",
			want:    false,
		},
		// Packages without version suffix (non-Maven should be false)
		{
			name:    "python package without sp suffix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.28.1",
			want:    false,
		},
		// Invalid version suffix patterns
		{
			name:    "version with sp but no number",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.28.1+sp",
			want:    false,
		},
		{
			name:    "version with seal suffix instead of sp",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.28.1+seal.1",
			want:    false,
		},
		{
			name:    "version with sp in the middle",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.28.1+sp1.beta",
			want:    false,
		},
		{
			name:    "empty version",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "",
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
