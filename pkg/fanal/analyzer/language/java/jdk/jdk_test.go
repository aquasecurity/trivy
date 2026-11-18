package jdk

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestJDKAnalyzer_Analyze(t *testing.T) {
	f, err := os.Open("testdata/release")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })

	got, err := jdkAnalyzer{}.Analyze(t.Context(), analyzer.AnalysisInput{
		FilePath: "usr/local/release",
		Content:  f,
	})
	require.NoError(t, err)
	assert.Equal(t, &analyzer.AnalysisResult{Applications: []types.Application{{
		Type:     types.JDK,
		FilePath: "usr/local/release",
		Packages: types.Packages{{
			ID:       "openjdk@17.0.13+11",
			Name:     "openjdk",
			Version:  "17.0.13+11",
			FilePath: "usr/local/release",
		}},
	}}}, got)
}

func TestJDKAnalyzer_Required(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{path: "usr/local/release", want: true},
		{path: "opt/java/openjdk/release", want: true},
		{path: "etc/os-release", want: false},
		{path: "usr/local/release.txt", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.want, jdkAnalyzer{}.Required(tt.path, nil))
		})
	}
}

func TestReleaseParser_Parse(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{
			name:    "corretto 17 with runtime build and LTS suffix",
			content: "IMPLEMENTOR=\"Amazon.com Inc.\"\nJAVA_RUNTIME_VERSION=\"17.0.13+11-LTS\"\nJAVA_VERSION=\"17.0.13\"\n",
			want:    "17.0.13+11",
		},
		{
			name:    "temurin 21 without runtime version",
			content: "IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\"21.0.5\"\n",
			want:    "21.0.5",
		},
		{
			name:    "ubuntu runtime version suffix stripped",
			content: "JAVA_VERSION=\"21.0.5\"\nJAVA_RUNTIME_VERSION=\"21.0.5+11-Ubuntu-1ubuntu124.04\"\n",
			want:    "21.0.5+11",
		},
		{
			name:    "legacy jdk 8 update format",
			content: "IMPLEMENTOR=\"Oracle Corporation\"\nJAVA_VERSION=\"1.8.0_432\"\nJAVA_RUNTIME_VERSION=\"1.8.0_432-b06\"\n",
			want:    "8.0.432+6",
		},
		{
			name:    "unrelated file named release",
			content: "RELEASE=2026.11\nCHANNEL=stable\n",
			want:    "",
		},
		{
			name:    "java_version without any jdk markers is ignored",
			content: "JAVA_VERSION=\"17.0.13\"\n",
			want:    "",
		},
		{
			name:    "invalid java version",
			content: "IMPLEMENTOR=\"Custom\"\nJAVA_VERSION=\"not-a-version\"\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs, deps, err := (parser{}).Parse(t.Context(), strings.NewReader(tt.content))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Empty(t, deps)
			if tt.want == "" {
				assert.Empty(t, pkgs)
				return
			}
			assert.Equal(t, []types.Package{{
				ID:      "openjdk@" + tt.want,
				Name:    "openjdk",
				Version: tt.want,
			}}, pkgs)
		})
	}
}
