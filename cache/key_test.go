package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithVersionSuffix(t *testing.T) {
	type args struct {
		key     string
		version string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "happy path",
			args: args{
				key:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				version: "111101112110013",
			},
			want: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e/111101112110013",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithVersionSuffix(tt.args.key, tt.args.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTrimVersionSuffix(t *testing.T) {
	type args struct {
		versioned string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "happy path",
			args: args{
				versioned: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e/111101112110013",
			},
			want: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TrimVersionSuffix(tt.args.versioned)
			assert.Equal(t, tt.want, got)
		})
	}
}
