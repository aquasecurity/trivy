package sbt

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_sbtDependencyLockAnalyzer(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "v1 lockfile",
			inputFile: "testdata/v1/build.sbt.lock",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Sbt,
						FilePath: "testdata/v1/build.sbt.lock",
						Packages: types.Packages{
							{
								ID:      "org.apache.commons:commons-lang3:3.9",
								Name:    "org.apache.commons:commons-lang3",
								Version: "3.9",
								Locations: []types.Location{
									{
										StartLine: 10,
										EndLine:   25,
									},
								},
							},
							{
								ID:      "org.scala-lang:scala-library:2.12.10",
								Name:    "org.scala-lang:scala-library",
								Version: "2.12.10",
								Locations: []types.Location{
									{
										StartLine: 26,
										EndLine:   41,
									},
								},
							},
							{
								ID:      "org.typelevel:cats-core_2.12:2.9.0",
								Name:    "org.typelevel:cats-core_2.12",
								Version: "2.9.0",
								Locations: []types.Location{
									{
										StartLine: 42,
										EndLine:   57,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "empty lockfile",
			inputFile: "testdata/empty/build.sbt.lock",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			a := sbtDependencyLockAnalyzer{}
			ctx := context.Background()

			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
