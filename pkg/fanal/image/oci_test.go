package image

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

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
				require.ErrorContains(t, err, test.wantErr, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestTryOCI_PathWithSeparators(t *testing.T) {
	// A layout directory may itself contain '@' or ':': Jenkins names workspaces
	// "job@2" and "job@tmp", and timestamps put ':' in directory names.
	dirs := []string{"job@tmp", "job@2"}
	if runtime.GOOS != "windows" {
		dirs = append(dirs, "2026-10-26T10:00:00")
	}
	for _, dir := range dirs {
		t.Run(dir, func(t *testing.T) {
			root := t.TempDir()
			// The directory without the suffix exists too, as a Jenkins workspace does beside "job@tmp".
			require.NoError(t, os.MkdirAll(filepath.Join(root, "job"), 0o755))
			layoutDir := filepath.Join(root, dir, "layout")
			require.NoError(t, os.CopyFS(layoutDir, os.DirFS(filepath.Join("testdata", "single"))))

			_, err := tryOCI(layoutDir)
			require.NoError(t, err)

			_, err = tryOCI(layoutDir + ":3.14")
			require.NoError(t, err)

			_, err = tryOCI(layoutDir + "@sha256:56ae38f2f5c54b98311b8b2463d4861368c451ac17098f4227d84946b42ab96d")
			require.NoError(t, err)

			_, err = tryOCI(layoutDir + ":3.11")
			require.ErrorContains(t, err, "invalid OCI image ref")
		})
	}
}
