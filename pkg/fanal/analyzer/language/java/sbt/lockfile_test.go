package sbt

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func Test_sbtDependencyLockAnalyzer(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "empty lockfile",
			dir:  "testdata/empty",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Sbt,
						FilePath: "build.sbt.lock",
						Packages: types.Packages{},
					},
				},
			},
		},
		{
			name: "v1 lockfile",
			dir:  "testdata/v1",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Sbt,
						FilePath: "build.sbt.lock",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newSbtDependencyLockAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(context.Background(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
