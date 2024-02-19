package gradle

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func Test_parseBuildGradle(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     []string
	}{
		{
			name:     "happy path",
			filePath: filepath.Join("testdata", "buildgradlefiles", "happy.build.gradle"),
			want: []string{
				"junit:junit:4.13",
				"org.eclipse.jgit:org.eclipse.jgit:4.9.2.201712150930-r",
				"com.android.support:appcompat-v7:23.1.1",
				"com.googlecode.jsontoken:jsontoken:1.1",
				"com.googlecode.jsontoken:jsontoken:1.1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.filePath)
			require.NoError(t, err)

			got := parseBuildGradle(f)
			require.Equal(t, tt.want, got)
		})
	}
}
