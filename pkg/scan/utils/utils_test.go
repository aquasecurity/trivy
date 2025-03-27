package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestFormatSrcVersion(t *testing.T) {
	tests := []struct {
		name string
		pkg  types.Package
		want string
	}{
		{
			name: "happy path",
			pkg: types.Package{
				SrcVersion: "1.2.3",
				SrcRelease: "1",
			},
			want: "1.2.3-1",
		},
		{
			name: "with epoch",
			pkg: types.Package{
				SrcEpoch:   2,
				SrcVersion: "1.2.3",
				SrcRelease: "alpha",
			},
			want: "2:1.2.3-alpha",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatSrcVersion(tt.pkg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFormatVersion(t *testing.T) {
	tests := []struct {
		name string
		pkg  types.Package
		want string
	}{
		{
			name: "happy path",
			pkg: types.Package{
				Version: "1.2.3",
				Release: "1",
			},
			want: "1.2.3-1",
		},
		{
			name: "with epoch",
			pkg: types.Package{
				Epoch:   2,
				Version: "1.2.3",
				Release: "alpha",
			},
			want: "2:1.2.3-alpha",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatVersion(tt.pkg)
			assert.Equal(t, tt.want, got)
		})
	}
}
