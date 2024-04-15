package gradle

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func Test_parsePom(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		inputPath string
		want      pomXML
	}{
		{
			name:      "happy path",
			inputFile: filepath.Join("testdata", "poms", "happy.pom"),
			inputPath: "cache/caches/modules-2/files-2.1/org.example/example-core/1.0/872e413497b906e7c9fa85ccc96046c5d1ef7ece/example-core-1.0.pom",
			want: pomXML{
				GroupId:    "org.example",
				ArtifactId: "example-core",
				Version:    "1.0.0",
				Licenses: Licenses{
					License: []License{
						{
							Name: "Apache License, Version 2.0",
						},
					},
				},
				Dependencies: Dependencies{
					Dependency: []Dependency{
						{
							GroupID:    "org.example",
							ArtifactID: "example-api",
							Version:    "2.0.0",
						},
					},
				},
			},
		},
		{
			name:      "happy path. Take GroupID and Version from path",
			inputFile: filepath.Join("testdata", "poms", "without-groupid-and-version.pom"),
			inputPath: "cache/caches/modules-2/files-2.1/org.example/example-core/1.0.0/872e413497b906e7c9fa85ccc96046c5d1ef7ece/example-core-1.0.pom",
			want: pomXML{
				GroupId:    "org.example",
				ArtifactId: "example-core",
				Version:    "1.0.0",
				Licenses: Licenses{
					License: []License{
						{
							Name: "Apache License, Version 2.0",
						},
					},
				},
			},
		},
		{
			name:      "happy path. Dependency version as property.",
			inputFile: filepath.Join("testdata", "poms", "dep-version-as-property.pom"),
			inputPath: "cache/caches/modules-2/files-2.1/org.example/example-core/1.0.0/872e413497b906e7c9fa85ccc96046c5d1ef7ece/example-core-1.0.pom",
			want: pomXML{
				GroupId:    "org.example",
				ArtifactId: "example-core",
				Version:    "1.0.0",
				Properties: Properties{
					"coreVersion": "2.0.1",
				},
				Dependencies: Dependencies{
					Dependency: []Dependency{
						{
							GroupID:    "org.example",
							ArtifactID: "example-api",
							Version:    "2.0.1",
						},
					},
				},
			},
		},
		{
			name:      "happy path. Dependency version as property.",
			inputFile: filepath.Join("testdata", "poms", "without-licenses-and-deps.pom"),
			inputPath: "cache/caches/modules-2/files-2.1/org.example/example-core/1.0.0/872e413497b906e7c9fa85ccc96046c5d1ef7ece/example-core-1.0.pom",
			want:      pomXML{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			pom, err := parsePom(f, tt.inputPath)
			require.NoError(t, err)

			require.Equal(t, tt.want, pom)
		})
	}
}
