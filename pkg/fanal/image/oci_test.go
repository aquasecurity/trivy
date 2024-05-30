package image

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTryOCI(t *testing.T) {
	tests := []struct {
		name         string
		ociImagePath string
		wantErr      string
	}{
		{
			name:         "correct path to index without tag",
			ociImagePath: filepath.Join("testdata", "multi"),
			wantErr:      "",
		},
		{
			name:         "correct path to index with correct tag",
			ociImagePath: filepath.Join("testdata", "multi:tg11"),
			wantErr:      "",
		},
		{
			name:         "correct path to index with incorrect tag",
			ociImagePath: filepath.Join("testdata", "multi:tg12"),
			wantErr:      "invalid OCI image ref",
		},
		{
			name:         "correct path to manifest without tag",
			ociImagePath: filepath.Join("testdata", "single"),
			wantErr:      "",
		},
		{
			name:         "correct path to manifest with correct tag",
			ociImagePath: filepath.Join("testdata", "single:3.14"),
			wantErr:      "",
		},
		{
			name:         "correct path to manifest with incorrect tag",
			ociImagePath: filepath.Join("testdata", "single:3.11"),
			wantErr:      "invalid OCI image ref",
		},
		{
			name: "correct path to manifest with correct digest",
			ociImagePath: filepath.Join("testdata",
				"single@sha256:56ae38f2f5c54b98311b8b2463d4861368c451ac17098f4227d84946b42ab96d"),
			wantErr: "",
		},
		{
			name: "correct path to manifest with incorrect digest",
			ociImagePath: filepath.Join("testdata",
				"single@sha256:1111111111111111111111111111111111111111111111111111111111111111"),
			wantErr: "invalid OCI image ref",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := tryOCI(test.ociImagePath)
			if test.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantErr, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
