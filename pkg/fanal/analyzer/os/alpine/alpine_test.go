package alpine

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestAlpineReleaseOSAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name       string
		input      analyzer.AnalysisInput
		wantResult *analyzer.AnalysisResult
		wantError  string
	}{
		{
			name: "happy path",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/alpine-release",
				Content:  strings.NewReader("3.15.4"),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.Alpine,
					Name:   "3.15.4",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := alpineOSAnalyzer{}
			res, err := a.Analyze(t.Context(), test.input)

			if test.wantError != "" {
				require.Error(t, err)
				assert.Equal(t, test.wantError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.wantResult, res)
			}
		})
	}
}
