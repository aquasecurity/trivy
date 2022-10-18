package secret_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestSecretAnalyzer(t *testing.T) {
	wantFinding1 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 2,
		EndLine:   2,
		Match:     "generic secret line secret=\"*********\"",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      1,
					Content:     "--- ignore block start ---",
					IsCause:     false,
					Annotation:  "",
					Truncated:   false,
					Highlighted: "--- ignore block start ---",
					FirstCause:  false,
					LastCause:   false,
				},
				{
					Number:      2,
					Content:     "generic secret line secret=\"*********\"",
					IsCause:     true,
					Annotation:  "",
					Truncated:   false,
					Highlighted: "generic secret line secret=\"*********\"",
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      3,
					Content:     "--- ignore block stop ---",
					IsCause:     false,
					Annotation:  "",
					Truncated:   false,
					Highlighted: "--- ignore block stop ---",
					FirstCause:  false,
					LastCause:   false,
				},
			},
		},
	}
	wantFinding2 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 4,
		EndLine:   4,
		Match:     "secret=\"**********\"",
		Code: types.Code{
			Lines: []types.Line{
				{
					Number:      2,
					Content:     "generic secret line secret=\"*********\"",
					IsCause:     false,
					Highlighted: "generic secret line secret=\"*********\"",
				},
				{
					Number:      3,
					Content:     "--- ignore block stop ---",
					IsCause:     false,
					Highlighted: "--- ignore block stop ---",
				},
				{
					Number:      4,
					Content:     "secret=\"**********\"",
					IsCause:     true,
					Highlighted: "secret=\"**********\"",
					FirstCause:  true,
					LastCause:   true,
				},
				{
					Number:      5,
					Content:     "credentials: { user: \"username\" password: \"123456789\" }",
					Highlighted: "credentials: { user: \"username\" password: \"123456789\" }",
				},
			},
		},
	}
	tests := []struct {
		name       string
		configPath string
		filePath   string
		dir        string
		want       *analyzer.AnalysisResult
	}{
		{
			name:       "return results",
			configPath: filepath.Join("testdata", "config.yaml"),
			filePath:   filepath.Join("testdata", "secret.txt"),
			dir:        ".",
			want: &analyzer.AnalysisResult{
				Secrets: []types.Secret{
					{
						FilePath: filepath.Join("testdata", "secret.txt"),
						Findings: []types.SecretFinding{wantFinding1, wantFinding2},
					},
				},
			},
		},
		{
			name:       "image scan return result",
			configPath: filepath.Join("testdata", "image-config.yaml"),
			filePath:   filepath.Join("testdata", "secret.txt"),
			want: &analyzer.AnalysisResult{
				Secrets: []types.Secret{
					{
						FilePath: "/testdata/secret.txt",
						Findings: []types.SecretFinding{wantFinding1, wantFinding2},
					},
				},
			},
		},
		{
			name:       "image scan return nil",
			configPath: filepath.Join("testdata", "image-config.yaml"),
			filePath:   filepath.Join("testdata", "secret.doc"),
			want:       nil,
		},
		{
			name:       "return nil when no results",
			configPath: "",
			filePath:   filepath.Join("testdata", "secret.txt"),
			want:       nil,
		},
		{
			name:       "skip binary file",
			configPath: "",
			filePath:   filepath.Join("testdata", "binaryfile"),
			want:       nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &secret.SecretAnalyzer{}
			err := a.Init(analyzer.AnalyzerOptions{
				SecretScannerOption: analyzer.SecretScannerOption{ConfigPath: tt.configPath},
			})
			require.NoError(t, err)
			content, err := os.Open(tt.filePath)
			require.NoError(t, err)
			fi, err := content.Stat()
			require.NoError(t, err)

			got, err := a.Analyze(context.TODO(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Dir:      tt.dir,
				Content:  content,
				Info:     fi,
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSecretRequire(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "pass regular file",
			filePath: filepath.Join("testdata", "secret.txt"),
			want:     true,
		},
		{
			name:     "skip small file",
			filePath: filepath.Join("testdata", "emptyfile"),
			want:     false,
		},
		{
			name:     "skip folder",
			filePath: "testdata/node_modules/secret.txt",
			want:     false,
		},
		{
			name:     "skip file",
			filePath: filepath.Join("testdata", "package-lock.json"),
			want:     false,
		},
		{
			name:     "skip extension",
			filePath: filepath.Join("testdata", "secret.doc"),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := secret.SecretAnalyzer{}
			err := a.Init(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			fi, err := os.Stat(tt.filePath)
			require.NoError(t, err)

			got := a.Required(tt.filePath, fi)
			assert.Equal(t, tt.want, got)
		})
	}
}
