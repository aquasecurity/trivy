package apk

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	aos "github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_apkRepoAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		input   analyzer.AnalysisInput
		want    *analyzer.AnalysisResult
		wantErr string
	}{
		{
			name: "alpine",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("http://nl.alpinelinux.org/alpine/v3.7/main"),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.7"},
			},
		},
		{
			name: "adelie",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://distfiles.adelielinux.org/adelie/1.0-beta4/system/"),
			},
			want: nil,
		},
		{
			name: "repository has 'http' schema",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("http://nl.alpinelinux.org/alpine/v3.7/main"),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.7"},
			},
		},
		{
			name: "repository has 'https' schema",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://dl-cdn.alpinelinux.org/alpine/v3.15/main"),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.15"},
			},
		},
		{
			name: "repository has 'ftp' schema",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("ftp://dl-3.alpinelinux.org/alpine/v2.6/main"),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "2.6"},
			},
		},
		{
			name: "edge version",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://dl-cdn.alpinelinux.org/alpine/edge/main"),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "edge"},
			},
		},
		{
			name: "happy path. 'etc/apk/repositories' contains some line with v* versions",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content: strings.NewReader(`https://dl-cdn.alpinelinux.org/alpine/v3.1/main

https://dl-cdn.alpinelinux.org/alpine/v3.10/main
`),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.10"},
			},
		},
		{
			name: "multiple v* versions",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content: strings.NewReader(`https://dl-cdn.alpinelinux.org/alpine/v3.10/main
https://dl-cdn.alpinelinux.org/alpine/v3.1/main
`),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "3.10"},
			},
		},
		{
			name: "multiple v* and edge versions",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content: strings.NewReader(`https://dl-cdn.alpinelinux.org/alpine/edge/main
https://dl-cdn.alpinelinux.org/alpine/v3.10/main
`),
			},
			want: &analyzer.AnalysisResult{
				Repository: &types.Repository{Family: aos.Alpine, Release: "edge"},
			},
		},
		{
			name: "sad path",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/apk/repositories",
				Content:  strings.NewReader("https://dl-cdn.alpinelinux.org/alpine//edge/main"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := apkRepoAnalyzer{}
			got, err := a.Analyze(context.Background(), test.input)

			if test.wantErr != "" {
				assert.Error(t, err)
				assert.Equal(t, test.wantErr, err.Error())
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}
