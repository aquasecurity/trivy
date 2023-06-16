package dockerfile

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_dockerConfigAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "dockerfile",
			filePath: "dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile",
			filePath: "Dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile with ext",
			filePath: "Dockerfile.build",
			want:     true,
		},
		{
			name:     "dockerfile as ext",
			filePath: "build.dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile in dir",
			filePath: "docker/Dockerfile",
			want:     true,
		},
		{
			name:     "Dockerfile as prefix",
			filePath: "Dockerfilebuild",
			want:     false,
		},
		{
			name:     "Dockerfile as suffix",
			filePath: "buildDockerfile",
			want:     false,
		},
		{
			name:     "Dockerfile as prefix with ext",
			filePath: "Dockerfilebuild.sh",
			want:     false,
		},
		{
			name:     "Dockerfile as suffix with ext",
			filePath: "buildDockerfile.sh",
			want:     false,
		},
		{
			name:     "json",
			filePath: "deployment.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := dockerConfigAnalyzer{}
			got := s.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
