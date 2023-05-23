package image

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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
			wantErr:      "invalid OCI image tag",
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
			wantErr:      "invalid OCI image tag",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := tryOCI(test.ociImagePath)
			if test.wantErr != "" {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), test.wantErr, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
