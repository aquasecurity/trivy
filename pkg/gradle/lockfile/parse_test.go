package lockfile

import (
	"os"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lockfile",
			want: []types.Library{
				{
					Name:    "cglib:cglib-nodep",
					Version: "2.1.2",
				},
				{
					Name:    "org.springframework:spring-asm",
					Version: "3.1.3.RELEASE",
				},
				{
					Name:    "org.springframework:spring-beans",
					Version: "5.0.5.RELEASE",
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/empty.lockfile",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			f, err := os.Open(tt.inputFile)
			assert.NoError(t, err)

			libs, _, _ := parser.Parse(f)
			assert.Equal(t, tt.want, libs)
		})
	}
}
