package swift

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_swiftLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy/Package.resolved",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Swift,
						FilePath: "testdata/happy/Package.resolved",
						Packages: types.Packages{
							{
								ID:      "github.com/Quick/Nimble@9.2.1",
								Name:    "github.com/Quick/Nimble",
								Version: "9.2.1",
								Locations: []types.Location{
									{
										StartLine: 4,
										EndLine:   12,
									},
								},
							},
							{
								ID:      "github.com/Quick/Quick@7.0.0",
								Name:    "github.com/Quick/Quick",
								Version: "7.0.0",
								Locations: []types.Location{
									{
										StartLine: 13,
										EndLine:   21,
									},
								},
							},
							{
								ID:      "github.com/ReactiveCocoa/ReactiveSwift@7.1.1",
								Name:    "github.com/ReactiveCocoa/ReactiveSwift",
								Version: "7.1.1",
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   30,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "empty file",
			inputFile: "testdata/empty/Package.resolved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := swiftLockAnalyzer{}
			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_swiftLockAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "Package.resolved",
			filePath: "path/to/Package.resolved",
			want:     true,
		},
		{
			name:     ".package.resolved (Tuist)",
			filePath: "path/to/.package.resolved",
			want:     true,
		},
		{
			name:     "unrelated file",
			filePath: "path/to/Package.swift",
			want:     false,
		},
	}

	a := swiftLockAnalyzer{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}
