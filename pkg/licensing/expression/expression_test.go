package expression

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeForSPDX(t *testing.T) {
	tests := []struct {
		name    string
		license string
		want    string
	}{
		{
			name:    "happy path",
			license: "AFL 2.0",
			want:    "AFL-2.0",
		},
		{
			name:    "happy path with WITH section",
			license: "AFL 2.0 with Linux-syscall-note exception",
			want:    "AFL-2.0 WITH Linux-syscall-note-exception",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, NormalizeForSPDX(tt.license), "NormalizeWithExpression(%v)", tt.license)
		})
	}
}
