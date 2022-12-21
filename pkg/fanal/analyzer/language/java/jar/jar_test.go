package jar

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_javaLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path (WAR file)",
			inputFile: "testdata/test.war",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Jar,
						FilePath: "testdata/test.war",
						Libraries: []types.Package{
							{
								Name:     "org.glassfish:javax.el",
								FilePath: "testdata/test.war",
								Version:  "3.0.0",
							},
							{
								Name:     "com.fasterxml.jackson.core:jackson-databind",
								FilePath: "testdata/test.war",
								Version:  "2.9.10.6",
							},
							{
								Name:     "com.fasterxml.jackson.core:jackson-annotations",
								FilePath: "testdata/test.war",
								Version:  "2.9.10",
							},
							{
								Name:     "com.fasterxml.jackson.core:jackson-core",
								FilePath: "testdata/test.war",
								Version:  "2.9.10",
							},
							{
								Name:     "org.slf4j:slf4j-api",
								FilePath: "testdata/test.war",
								Version:  "1.7.30",
							},
							{
								Name:     "com.cronutils:cron-utils",
								FilePath: "testdata/test.war",
								Version:  "9.1.2",
							},
							{
								Name:     "org.apache.commons:commons-lang3",
								FilePath: "testdata/test.war",
								Version:  "3.11",
							},
							{
								Name:     "com.example:web-app",
								FilePath: "testdata/test.war",
								Version:  "1.0-SNAPSHOT",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path (PAR file)",
			inputFile: "testdata/test.par",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Jar,
						FilePath: "testdata/test.par",
						Libraries: []types.Package{
							{
								Name:     "com.fasterxml.jackson.core:jackson-core",
								FilePath: "testdata/test.par",
								Version:  "2.9.10",
							},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/test.txt",
			wantErr:   "not a valid zip file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			stat, err := f.Stat()
			require.NoError(t, err)

			a := javaLibraryAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Info:     stat,
				Content:  f,
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_javaLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "war",
			filePath: "test/test.war",
			want:     true,
		},
		{
			name:     "jar",
			filePath: "test.jar",
			want:     true,
		},
		{
			name:     "ear",
			filePath: "a/b/c/d/test.ear",
			want:     true,
		},
		{
			name:     "capital jar",
			filePath: "a/b/c/d/test.JAR",
			want:     true,
		},
		{
			name:     "zip",
			filePath: "test.zip",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := javaLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
