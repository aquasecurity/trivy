package gradle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_parseBuildGradle(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want []string
	}{
		{
			name: "happy path",
			dir:  "happy",
			want: []string{
				"junit:junit:4.13",
				"org.eclipse.jgit:org.eclipse.jgit:4.9.2.201712150930-r",
				"com.android.support:appcompat-v7:23.1.1",
				"com.googlecode.jsontoken:jsontoken:1.1",
				"com.googlecode.jsontoken:jsontoken:1.1",
			},
		},
		{
			name: "happy path. build.gradle.kts file",
			dir:  "kts-file",
			want: []string{
				"org.eclipse.jgit:org.eclipse.jgit:4.9.2.201712150930-r",
			},
		},
		{
			name: "happy path. Single line.",
			dir:  "single-line",
			want: []string{
				"junit:junit:4.13",
			},
		},
		{
			name: "happy path. There are no dependencies",
			dir:  "empty",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := os.DirFS(filepath.Join("testdata", "buildgradlefiles"))

			got, _, err := parseBuildGradle(f, tt.dir)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
