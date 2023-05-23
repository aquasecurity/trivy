package analyzer_test

import (
	"context"
	"errors"
	"os"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type mockConfigAnalyzer struct{}

func newMockConfigAnalyzer(_ analyzer.ConfigAnalyzerOptions) (analyzer.ConfigAnalyzer, error) {
	return mockConfigAnalyzer{}, nil
}

func (mockConfigAnalyzer) Required(targetOS types.OS) bool {
	return targetOS.Family == "alpine"
}

func (mockConfigAnalyzer) Analyze(_ context.Context, input analyzer.ConfigAnalysisInput) (*analyzer.ConfigAnalysisResult, error) {
	if input.Config == nil {
		return nil, errors.New("error")
	}
	return &analyzer.ConfigAnalysisResult{
		HistoryPackages: types.Packages{
			{
				Name:    "musl",
				Version: "1.1.24-r2",
			},
		},
	}, nil
}

func (mockConfigAnalyzer) Type() analyzer.Type {
	return analyzer.Type("test")
}

func (mockConfigAnalyzer) Version() int {
	return 1
}

func TestMain(m *testing.M) {
	mock := mockConfigAnalyzer{}
	analyzer.RegisterConfigAnalyzer(mock.Type(), newMockConfigAnalyzer)
	defer analyzer.DeregisterConfigAnalyzer(mock.Type())
	os.Exit(m.Run())
}

func TestAnalyzeConfig(t *testing.T) {
	type args struct {
		targetOS          types.OS
		config            *v1.ConfigFile
		disabledAnalyzers []analyzer.Type
		filePatterns      []string
	}
	tests := []struct {
		name string
		args args
		want *analyzer.ConfigAnalysisResult
	}{
		{
			name: "happy path",
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
				config: &v1.ConfigFile{
					OS: "linux",
				},
			},
			want: &analyzer.ConfigAnalysisResult{
				HistoryPackages: []types.Package{
					{
						Name:    "musl",
						Version: "1.1.24-r2",
					},
				},
			},
		},
		{
			name: "non-target OS",
			args: args{
				targetOS: types.OS{
					Family: "debian",
					Name:   "9.2",
				},
				config: &v1.ConfigFile{
					OS: "linux",
				},
			},
			want: &analyzer.ConfigAnalysisResult{},
		},
		{
			name: "Analyze returns an error",
			args: args{
				targetOS: types.OS{
					Family: "alpine",
					Name:   "3.11.6",
				},
			},
			want: &analyzer.ConfigAnalysisResult{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := analyzer.NewConfigAnalyzerGroup(analyzer.ConfigAnalyzerOptions{
				FilePatterns:      tt.args.filePatterns,
				DisabledAnalyzers: tt.args.disabledAnalyzers,
			})
			require.NoError(t, err)
			got := a.AnalyzeImageConfig(context.Background(), tt.args.targetOS, tt.args.config)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConfigAnalyzerGroup_AnalyzerVersions(t *testing.T) {
	tests := []struct {
		name     string
		disabled []analyzer.Type
		want     analyzer.Versions
	}{
		{
			name:     "happy path",
			disabled: []analyzer.Type{},
			want: analyzer.Versions{
				Analyzers: map[string]int{
					"apk-command": 1,
					"test":        1,
				},
			},
		},
		{
			name: "disable analyzers",
			disabled: []analyzer.Type{
				analyzer.TypeAlpine,
				analyzer.TypeApkCommand,
			},
			want: analyzer.Versions{
				Analyzers: map[string]int{
					"test": 1,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := analyzer.NewConfigAnalyzerGroup(analyzer.ConfigAnalyzerOptions{
				DisabledAnalyzers: tt.disabled,
			})
			require.NoError(t, err)
			got := a.AnalyzerVersions()
			assert.Equal(t, tt.want, got)
		})
	}
}
