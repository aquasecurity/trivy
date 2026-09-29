package secret_test

import (
	"cmp"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// fakeFileInfo lets Required tests use synthetic scan-relative paths without
// needing the path to exist on disk; Required only reads Size().
type fakeFileInfo struct{ size int64 }

func (f fakeFileInfo) Name() string       { return "" }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() os.FileMode  { return 0 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

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

// TestSecretAnalyzerInitReParseGuard checks that a repeated Init() with a
// non-canonical config path (e.g. one containing "/./") hits the re-init
// guard and does not re-parse the config.
func TestSecretAnalyzerInitReParseGuard(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "trivy-secret.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("{}\n"), 0o600))

	// Non-canonical form of the same path (contains "/./"), which Init normalizes via cleanPath.
	nonCanonical := filepath.Dir(configPath) + string(filepath.Separator) + "." + string(filepath.Separator) + filepath.Base(configPath)

	opt := analyzer.AnalyzerOptions{
		SecretScannerOption: analyzer.SecretScannerOption{ConfigPath: nonCanonical},
	}

	a := secret.SecretAnalyzer{}
	require.NoError(t, a.Init(opt))

	// Break the config so any re-parse would fail with a decode error.
	require.NoError(t, os.WriteFile(configPath, []byte("- not\n- a\n- mapping\n"), 0o600))

	// The second Init() must hit the re-init guard and skip parsing the (now broken) file.
	require.NoError(t, a.Init(opt), "second Init() re-parsed the config: the re-init guard did not fire for a non-canonical path")
}

func TestSecretRequire(t *testing.T) {
	const defaultConfig = "testdata/skip-tests-config.yaml"

	tests := []struct {
		name       string
		configPath string
		filePath   string
		size       int64
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
			size:       5,
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
			name:       "skip config file when configPath has a scan-root prefix and filePath is the tail",
			configPath: "testdata/fixtures/repo/secrets/trivy-secret.yaml",
			filePath:   "trivy-secret.yaml",
			want:       false,
		},
		{
			name:       "do not skip file whose basename matches but path boundary does not",
			configPath: "trivy-secret.yaml",
			filePath:   "my-trivy-secret.yaml",
			want:       true,
		},
		{
			// Known limitation of the path-suffix match: an unrelated file at the scan
			// root whose name equals the configPath's tail is also skipped. This locks
			// in the trade-off documented in Required so a refactor cannot silently
			// change it.
			name:       "over-skip: configPath suffix matches unrelated file at scan root",
			configPath: "configs/myconfig.yaml",
			filePath:   "myconfig.yaml",
			want:       false,
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

			size := cmp.Or(tt.size, 1024)
			got := a.Required(tt.filePath, fakeFileInfo{size: size})
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSecretRequireCustomSkips(t *testing.T) {
	// Custom config replaces the default skip-patterns entirely.
	// Verify that custom patterns are skipped and former defaults are no longer skipped.
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "skip custom dir (vendor)",
			filePath: "testdata/vendor/secret.txt",
			want:     false,
		},
		{
			name:     "no longer skip default dir (node_modules)",
			filePath: "testdata/node_modules/secret.txt",
			want:     true,
		},
		{
			name:     "skip custom file (custom.lock)",
			filePath: "testdata/custom.lock",
			want:     false,
		},
		{
			name:     "no longer skip default file (package-lock.json)",
			filePath: "testdata/package-lock.json",
			want:     true,
		},
		{
			name:     "skip custom extension (.xyz)",
			filePath: "testdata/secret.xyz",
			want:     false,
		},
		{
			name:     "no longer skip default extension (.doc)",
			filePath: "testdata/secret.doc",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := secret.SecretAnalyzer{}
			err := a.Init(analyzer.AnalyzerOptions{
				SecretScannerOption: analyzer.SecretScannerOption{
					ConfigPath: "testdata/custom-skip-config.yaml",
				},
			})
			require.NoError(t, err)

			fi, err := os.Stat(tt.filePath)
			require.NoError(t, err)

			got := a.Required(tt.filePath, fi)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSecretRequireEmptySkips(t *testing.T) {
	// When skip-patterns is explicitly set to empty, nothing should be skipped —
	// even paths that match the default skip patterns.
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "default skip dir (node_modules) is no longer skipped",
			filePath: "testdata/node_modules/secret.txt",
			want:     true,
		},
		{
			name:     "default skip file (package-lock.json) is no longer skipped",
			filePath: "testdata/package-lock.json",
			want:     true,
		},
		{
			name:     "default skip extension (.doc) is no longer skipped",
			filePath: "testdata/secret.doc",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := secret.SecretAnalyzer{}
			err := a.Init(analyzer.AnalyzerOptions{
				SecretScannerOption: analyzer.SecretScannerOption{
					ConfigPath: "testdata/empty-skip-config.yaml",
				},
			})
			require.NoError(t, err)

			fi, err := os.Stat(tt.filePath)
			require.NoError(t, err)

			got := a.Required(tt.filePath, fi)
			assert.Equal(t, tt.want, got)
		})
	}
}
