package expression

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name    string
		license string
		fn      NormalizeFunc
		want    string
		wantErr string
	}{
		{
			name:    "SPDX, space",
			license: "AFL 2.0",
			fn:      NormalizeForSPDX,
			want:    "AFL-2.0",
		},
		{
			name:    "SPDX, exception",
			license: "AFL 2.0 with Linux-syscall-note exception",
			fn:      NormalizeForSPDX,
			want:    "AFL-2.0 WITH Linux-syscall-note-exception",
		},
		{
			name:    "SPDX, invalid chars",
			license: "LGPL_2.1_only or MIT OR BSD-3>Clause",
			fn:      NormalizeForSPDX,
			want:    "LGPL-2.1-only OR MIT OR BSD-3-Clause",
		},
		{
			name:    "upper",
			license: "LGPL-2.1-only OR MIT",
			fn:      strings.ToUpper,
			want:    "LGPL-2.1-ONLY OR MIT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Normalize(tt.license, tt.fn)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equalf(t, tt.want, got, "NormalizeWithExpression(%v)", tt.license)
		})
	}
}
