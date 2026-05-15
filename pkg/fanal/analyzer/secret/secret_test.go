package secret_test

import (
	"os"
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
		Offset: 55,
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
		Offset: 100,
	}
	wantFindingGH_PAT := types.SecretFinding{
		RuleID:    "github-fine-grained-pat",
		Category:  "GitHub",
		Title:     "GitHub Fine-grained personal access tokens",
		Severity:  "CRITICAL",
		StartLine: 1,
		EndLine:   1,
		Match:     "Binary file \"/testdata/secret.cpython-310.pyc\" matches a rule \"GitHub Fine-grained personal access tokens\"",
		Offset:    2,
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
			configPath: "testdata/config.yaml",
			filePath:   "testdata/secret.txt",
			dir:        ".",
			want: &analyzer.AnalysisResult{
				Secrets: []types.Secret{
					{
						FilePath: "testdata/secret.txt",
						Findings: []types.SecretFinding{
							wantFinding1,
							wantFinding2,
						},
					},
				},
			},
		},
		{
			name:       "image scan return result",
			configPath: "testdata/image-config.yaml",
			filePath:   "testdata/secret.txt",
			want: &analyzer.AnalysisResult{
				Secrets: []types.Secret{
					{
						FilePath: "/testdata/secret.txt",
						Findings: []types.SecretFinding{
							wantFinding1,
							wantFinding2,
						},
					},
				},
			},
		},
		{
			name:       "image scan return nil",
			configPath: "testdata/image-config.yaml",
			filePath:   "testdata/secret.doc",
			want:       nil,
		},
		{
			name:       "return nil when no results",
			configPath: "",
			filePath:   "testdata/secret.txt",
			want:       nil,
		},
		{
			name:       "skip binary file",
			configPath: "",
			filePath:   "testdata/binaryfile",
			want:       nil,
		},
		{
			name:       "python binary file",
			configPath: "testdata/skip-tests-config.yaml",
			filePath:   "testdata/secret.cpython-310.pyc",
			want: &analyzer.AnalysisResult{
				Secrets: []types.Secret{
					{
						FilePath: "/testdata/secret.cpython-310.pyc",
						Findings: []types.SecretFinding{
							wantFindingGH_PAT,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := secret.SecretAnalyzer{}
			err := a.Init(analyzer.AnalyzerOptions{
				SecretScannerOption: analyzer.SecretScannerOption{ConfigPath: tt.configPath},
			})
			require.NoError(t, err)
			content, err := os.Open(tt.filePath)
			require.NoError(t, err)
			fi, err := content.Stat()
			require.NoError(t, err)

			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
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
	const defaultConfig = "testdata/skip-tests-config.yaml"

	tests := []struct {
		name       string
		configPath string
		filePath   string
		want       bool
	}{
		{
			name:       "pass regular file",
			configPath: defaultConfig,
			filePath:   "testdata/secret.txt",
			want:       true,
		},
		{
			name:       "skip small file",
			configPath: defaultConfig,
			filePath:   "testdata/emptyfile",
			want:       false,
		},
		{
			name:       "skip folder",
			configPath: defaultConfig,
			filePath:   "testdata/node_modules/secret.txt",
			want:       false,
		},
		{
			name:       "skip file",
			configPath: defaultConfig,
			filePath:   "testdata/package-lock.json",
			want:       false,
		},
		{
			name:       "skip extension",
			configPath: defaultConfig,
			filePath:   "testdata/secret.doc",
			want:       false,
		},
		{
			name:       "skip config file when configPath is a relative path matching filePath",
			configPath: "testdata/skip-tests-config.yaml",
			filePath:   "testdata/skip-tests-config.yaml",
			want:       false,
		},
		{
			name:       "skip config file when configPath is a bare filename matching filePath",
			configPath: "skip-tests-config.yaml",
			filePath:   "skip-tests-config.yaml",
			want:       false,
		},
		{
			name:       "do not skip unrelated file sharing a path suffix with configPath",
			configPath: "foo/bar/myconfig.yaml",
			filePath:   "bar/myconfig.yaml",
			want:       true,
		},
		{
			name:       "do not skip file at scan root when configPath is in a subfolder",
			configPath: "configs/myconfig.yaml",
			filePath:   "myconfig.yaml",
			want:       true,
		},
		{
			name:       "do not skip file when configPath is empty",
			configPath: "",
			filePath:   "src/myfile.yaml",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := secret.SecretAnalyzer{}
			err := a.Init(analyzer.AnalyzerOptions{
				SecretScannerOption: analyzer.SecretScannerOption{
					ConfigPath: tt.configPath,
				},
			})
			require.NoError(t, err)

			// Stat a real file so fi.Size() passes the small-file check; the path
			// argument passed to Required can be a synthetic scan-relative path.
			statPath := tt.filePath
			if _, err := os.Stat(statPath); err != nil {
				statPath = defaultConfig
			}
			fi, err := os.Stat(statPath)
			require.NoError(t, err)

			got := a.Required(tt.filePath, fi)
			assert.Equal(t, tt.want, got)
		})
	}
}
