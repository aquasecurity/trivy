package secret_test

import (
	"os"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/secret"
	"github.com/aquasecurity/fanal/types"
)

func TestMain(m *testing.M) {
	logger, _ := zap.NewDevelopment(zap.IncreaseLevel(zapcore.FatalLevel))
	log.SetLogger(logger.Sugar())
	os.Exit(m.Run())
}

func TestSecretScanner(t *testing.T) {
	wantFinding1 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 2,
		EndLine:   2,
		Match:     "generic secret line secret=\"*****\"",
	}
	wantFinding2 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 4,
		EndLine:   4,
		Match:     "secret=\"*****\"",
	}
	wantFinding3 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 5,
		EndLine:   5,
		Match:     "credentials: { user: \"*****\" password: \"123456789\" }",
	}
	wantFinding4 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "HIGH",
		StartLine: 5,
		EndLine:   5,
		Match:     "credentials: { user: \"username\" password: \"*****\" }",
	}
	wantFinding5 := types.SecretFinding{
		RuleID:    "aws-access-key-id",
		Category:  secret.CategoryAWS,
		Title:     "AWS Access Key ID",
		Severity:  "CRITICAL",
		StartLine: 2,
		EndLine:   2,
		Match:     "AWS_ACCESS_KEY_ID=*****",
	}
	wantFinding6 := types.SecretFinding{
		RuleID:    "github-pat",
		Category:  secret.CategoryGitHub,
		Title:     "GitHub Personal Access Token",
		Severity:  "CRITICAL",
		StartLine: 1,
		EndLine:   1,
		Match:     "GITHUB_PAT=*****",
	}
	wantFinding7 := types.SecretFinding{
		RuleID:    "github-pat",
		Category:  secret.CategoryGitHub,
		Title:     "GitHub Personal Access Token",
		Severity:  "CRITICAL",
		StartLine: 1,
		EndLine:   1,
		Match:     "aaaaaaaaaaaaaaaaaa GITHUB_PAT=***** bbbbbbbbbbbbbbbbbbb",
	}
	wantFinding8 := types.SecretFinding{
		RuleID:    "rule1",
		Category:  "general",
		Title:     "Generic Rule",
		Severity:  "UNKNOWN",
		StartLine: 2,
		EndLine:   2,
		Match:     "generic secret line secret=\"*****\"",
	}

	tests := []struct {
		name          string
		configPath    string
		inputFilePath string
		want          types.Secret
	}{
		{
			name:          "find match",
			configPath:    "testdata/config.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding1, wantFinding2},
			},
		},
		{
			name:          "include when keyword found",
			configPath:    "testdata/config-happy-keywords.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding1, wantFinding2},
			},
		},
		{
			name:          "exclude when no keyword found",
			configPath:    "testdata/config-sad-keywords.yaml",
			inputFilePath: "testdata/secret.txt",
			want:          types.Secret{},
		},
		{
			name:          "should ignore .md files by default",
			configPath:    "testdata/config.yaml",
			inputFilePath: "testdata/secret.md",
			want: types.Secret{
				FilePath: "testdata/secret.md",
			},
		},
		{
			name:          "should disable .md allow rule",
			configPath:    "testdata/config-disable-allow-rule-md.yaml",
			inputFilePath: "testdata/secret.md",
			want: types.Secret{
				FilePath: "testdata/secret.md",
				Findings: []types.SecretFinding{wantFinding1, wantFinding2},
			},
		},
		{
			name:          "should find ghp builtin secret",
			configPath:    "",
			inputFilePath: "testdata/builtin-rule-secret.txt",
			want: types.Secret{
				FilePath: "testdata/builtin-rule-secret.txt",
				Findings: []types.SecretFinding{wantFinding5, wantFinding6},
			},
		},
		{
			name:          "should enable github-pat builtin rule, but disable aws-access-key-id rule",
			configPath:    "testdata/config-enable-ghp.yaml",
			inputFilePath: "testdata/builtin-rule-secret.txt",
			want: types.Secret{
				FilePath: "testdata/builtin-rule-secret.txt",
				Findings: []types.SecretFinding{wantFinding6},
			},
		},
		{
			name:          "should disable github-pat builtin rule",
			configPath:    "testdata/config-disable-ghp.yaml",
			inputFilePath: "testdata/builtin-rule-secret.txt",
			want: types.Secret{
				FilePath: "testdata/builtin-rule-secret.txt",
				Findings: []types.SecretFinding{wantFinding5},
			},
		},
		{
			name:          "should disable custom rule",
			configPath:    "testdata/config-disable-rule1.yaml",
			inputFilePath: "testdata/secret.txt",
			want:          types.Secret{},
		},
		{
			name:          "allow-rule path",
			configPath:    "testdata/allow-path.yaml",
			inputFilePath: "testdata/secret.txt",
			want:          types.Secret{},
		},
		{
			name:          "allow-rule regex",
			configPath:    "testdata/allow-regex.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding1},
			},
		},
		{
			name:          "exclude-block regexes",
			configPath:    "testdata/exclude-block.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding2},
			},
		},
		{
			name:          "global allow-rule path",
			configPath:    "testdata/global-allow-path.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: nil,
			},
		},
		{
			name:          "global allow-rule regex",
			configPath:    "testdata/global-allow-regex.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding1},
			},
		},
		{
			name:          "global exclude-block regexes",
			configPath:    "testdata/global-exclude-block.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding2},
			},
		},
		{
			name:          "multiple secret groups",
			configPath:    "testdata/multiple-secret-groups.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding3, wantFinding4},
			},
		},
		{
			name:          "truncate long line",
			inputFilePath: "testdata/long-line-secret.txt",
			want: types.Secret{
				FilePath: "testdata/long-line-secret.txt",
				Findings: []types.SecretFinding{wantFinding7},
			},
		},
		{
			name:          "add unknown severity when rule has no severity",
			configPath:    "testdata/config-without-severity.yaml",
			inputFilePath: "testdata/secret.txt",
			want: types.Secret{
				FilePath: "testdata/secret.txt",
				Findings: []types.SecretFinding{wantFinding8},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := secret.NewScanner(tt.configPath)
			require.NoError(t, err)

			content, err := os.ReadFile(tt.inputFilePath)
			require.NoError(t, err)

			got := s.Scan(secret.ScanArgs{
				FilePath: tt.inputFilePath,
				Content:  content},
			)
			assert.Equal(t, tt.want, got)
		})
	}
}
