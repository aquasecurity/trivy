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
		// Python (pip) - change name with "seal-" prefix
		{
			name:    "python package with seal- prefix",
			eco:     ecosystem.Pip,
			pkgName: "seal-requests",
			pkgVer:  "2.28.1+seal.1",
			want:    true,
		},
		{
			name:    "python package without seal- prefix",
			eco:     ecosystem.Pip,
			pkgName: "requests",
			pkgVer:  "2.28.1",
			want:    false,
		},
		{
			name:    "python package with seal- in the middle",
			eco:     ecosystem.Pip,
			pkgName: "my-seal-package",
			pkgVer:  "1.0.0",
			want:    false,
		},
		// Node (npm) - change namespace with "@seal-security/" prefix
		{
			name:    "node package with @seal-security/",
			eco:     ecosystem.Npm,
			pkgName: "@seal-security/ejs",
			pkgVer:  "3.1.8+seal.1",
			want:    true,
		},
		{
			name:    "node package without @seal-security/ namespace",
			eco:     ecosystem.Npm,
			pkgName: "ejs",
			pkgVer:  "3.1.8",
			want:    false,
		},
		{
			name:    "node package with different namespace",
			eco:     ecosystem.Npm,
			pkgName: "@other/package",
			pkgVer:  "1.0.0",
			want:    false,
		},
		// Golang - change name with "sealsecurity.io/" prefix
		{
			name:    "golang package with sealsecurity.io/ prefix",
			eco:     ecosystem.Go,
			pkgName: "sealsecurity.io/github.com/Masterminds/goutils",
			pkgVer:  "v1.1.1+seal.1",
			want:    true,
		},
		{
			name:    "golang package without sealsecurity.io/ prefix",
			eco:     ecosystem.Go,
			pkgName: "github.com/Masterminds/goutils",
			pkgVer:  "v1.1.1",
			want:    false,
		},
		{
			name:    "golang package with sealsecurity.io in path but not prefix",
			eco:     ecosystem.Go,
			pkgName: "github.com/sealsecurity.io/package",
			pkgVer:  "v1.0.0",
			want:    false,
		},
		// Java (Maven) - change groupId with "seal.sp1." or "seal.sp2." prefix
		{
			name:    "java package with seal.sp1. groupId prefix",
			eco:     ecosystem.Maven,
			pkgName: "seal.sp1.org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622+seal.1",
			want:    true,
		},
		{
			name:    "java package with seal.sp2. groupId prefix",
			eco:     ecosystem.Maven,
			pkgName: "seal.sp2.org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622+seal.2",
			want:    true,
		},
		{
			name:    "java package without seal.sp prefix",
			eco:     ecosystem.Maven,
			pkgName: "org.eclipse.jetty:jetty-http",
			pkgVer:  "9.4.48.v20220622",
			want:    false,
		},
		{
			name:    "java package with seal in artifactId but not groupId",
			eco:     ecosystem.Maven,
			pkgName: "org.example:seal-artifact",
			pkgVer:  "1.0.0",
			want:    false,
		},
		// Edge cases
		{
			name:    "empty package name",
			eco:     ecosystem.Pip,
			pkgName: "",
			pkgVer:  "1.0.0",
			want:    false,
		},
		{
			name:    "unsupported ecosystem",
			eco:     ecosystem.RubyGems,
			pkgName: "seal-activesupport",
			pkgVer:  "1.0.0",
			want:    false,
		},
		{
			name:    "case sensitivity - uppercase SEAL",
			eco:     ecosystem.Pip,
			pkgName: "SEAL-django",
			pkgVer:  "4.2.0",
			want:    true, // Should match after normalization
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

func TestSealSecurity_Name(t *testing.T) {
	s := SealSecurity{}
	got := s.Name()
	want := "seal"
	if got != want {
		t.Errorf("SealSecurity.Name() = %v, want %v", got, want)
	}
}
