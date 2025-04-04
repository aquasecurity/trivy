package alt

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestAltReleaseOSAnalyzer(t *testing.T) {
	tests := []struct {
		name       string
		input      analyzer.AnalysisInput
		wantResult *analyzer.AnalysisResult
		wantError  string
	}{
		{
			name: "real ALT Container os-release",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/os-release",
				Content: strings.NewReader(`
				NAME="ALT Container"
				VERSION="11"
				ID=altlinux
				CPE_NAME="cpe:/o:alt:container:11"
				`),
			},
			wantResult: &analyzer.AnalysisResult{
				OS: types.OS{
					Family: types.ALT,
					Name:   "cpe:/o:alt:container:11",
				},
			},
		},
		{
			name: "non-ALT distro",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/os-release",
				Content: strings.NewReader(`
				ID=ubuntu
				NAME="Ubuntu"
				VERSION="22.04 LTS"
				`),
			},
			wantResult: nil,
		},
		{
			name: "ALT without CPE_NAME",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/os-release",
				Content: strings.NewReader(`
				ID=altlinux
				NAME="ALT"
				VERSION="11"
				`),
			},
			wantError: "alt: unable to analyze OS information",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := altOSAnalyzer{}
			res, err := a.Analyze(t.Context(), test.input)

			if test.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.wantResult, res)
			}
		})
	}
}

