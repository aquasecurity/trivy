package dpkg

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_dpkgListAnalyzer_Analyze(t *testing.T) {
	systemFiles := []string{
		"/bin/tar",
		"/etc/rmt",
		"/usr/lib/mime/packages/tar",
		"/usr/sbin/rmt-tar",
		"/usr/sbin/tarcat",
		"/usr/share/doc/tar/AUTHORS",
		"/usr/share/doc/tar/NEWS.gz",
		"/usr/share/doc/tar/README.Debian",
		"/usr/share/doc/tar/THANKS.gz",
		"/usr/share/doc/tar/changelog.Debian.gz",
		"/usr/share/doc/tar/copyright",
		"/usr/share/man/man1/tar.1.gz",
		"/usr/share/man/man1/tarcat.1.gz",
		"/usr/share/man/man8/rmt-tar.8.gz",
	}
	tests := []struct {
		name     string
		filePath string
		testFile string
		want     *analyzer.AnalysisResult
		wantErr  bool
	}{
		{
			name:     "info list",
			filePath: "var/lib/dpkg/info/tar.list",
			testFile: "./testdata/tar.list",
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/info/tar.list",
						Packages: []types.Package{
							{
								Name:           "tar",
								InstalledFiles: systemFiles,
							},
						},
					},
				},
				SystemInstalledFiles: systemFiles,
			},
		},
		{
			name:     "info list with arch",
			filePath: "var/lib/dpkg/info/tar:amd64.list",
			testFile: "./testdata/tar.list",
			want: &analyzer.AnalysisResult{
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/dpkg/info/tar:amd64.list",
						Packages: []types.Package{
							{
								Name:           "tar:amd64",
								InstalledFiles: systemFiles,
							},
						},
					},
				},
				SystemInstalledFiles: systemFiles,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.testFile)
			require.NoError(t, err)

			input := analyzer.AnalysisInput{
				Content:  f,
				FilePath: tt.filePath,
			}
			a := newDpkgListAnalyzer()

			got, err := a.Analyze(context.Background(), input)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_dpkgListAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "var/lib/dpkg/info/bash.list",
			want:     true,
		},
		{
			name:     "happy path with arch",
			filePath: "var/lib/dpkg/info/zlib1g:amd64.list",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "var/lib/dpkg/status/bash.list",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newDpkgListAnalyzer()
			got := a.Required(tt.filePath, nil)
			require.Equal(t, tt.want, got)
		})
	}
}
