package gradle

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/gradle/verification_metadata"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_gradleVerificationMetadataAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "happy path",
			inputFile: "testdata/verificationMetadataFiles/happy/verification-metadata.xml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Gradle,
						FilePath: "testdata/verificationMetadataFiles/happy/verification-metadata.xml",
						Packages: types.Packages{
							{
								ID:           "ch.qos.logback:logback-classic:1.5.32",
								Name:         "ch.qos.logback:logback-classic",
								Version:      "1.5.32",
								Relationship: types.RelationshipUnknown,
							},
						},
					},
				},
			},
		},
		{
			name:      "empty file",
			inputFile: "testdata/verificationMetadataFiles/empty/verification-metadata.xml",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			a := &gradleVerificationMetadataAnalyzer{
				parser: verification_metadata.NewParser(),
			}
			ctx := t.Context()

			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
