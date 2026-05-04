package binary_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/binary"
)

func TestParseStdlibVersion(t *testing.T) {
	tests := []struct {
		name      string
		goVersion string
		want      string
	}{
		{
			name:      "plain version",
			goVersion: "go1.22.3",
			want:      "v1.22.3",
		},
		{
			name:      "Go <=1.25 GOEXPERIMENT format with space separator",
			goVersion: "go1.25.3 X:nodwarf5",
			want:      "v1.25.3",
		},
		{
			name:      "Go <=1.25 GOEXPERIMENT format with boringcrypto",
			goVersion: "go1.22.3 X:boringcrypto",
			want:      "v1.22.3",
		},
		{
			name:      "Go >=1.26 GOEXPERIMENT format with dash separator",
			goVersion: "go1.26.0-X:nodwarf5",
			want:      "v1.26.0",
		},
		{
			name:      "Go >=1.26 GOEXPERIMENT format with multiple experiments",
			goVersion: "go1.26.0-X:nodwarf5,someother",
			want:      "v1.26.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := binary.ParseStdlibVersion(tt.goVersion)
			assert.Equal(t, tt.want, got)
		})
	}
}
