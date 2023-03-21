package walker

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"

	"github.com/stretchr/testify/assert"
)

func Test_shouldSkipFile(t *testing.T) {
	if runtime.GOOS == os.Windows {
		t.Skip("glob paths are not supported on Windows")
	}

	testCases := []struct {
		skipFiles []string
		skipMap   map[string]bool
	}{
		{
			skipFiles: []string{filepath.Join("/etc/*")},
			skipMap: map[string]bool{
				filepath.Join("/etc/foo"):     true,
				filepath.Join("/etc/foo/bar"): false,
			},
		},
		{
			skipFiles: []string{filepath.Join("/etc/*/*")},
			skipMap: map[string]bool{
				filepath.Join("/etc/foo"):     false,
				filepath.Join("/etc/foo/bar"): true,
			},
		},
		{
			skipFiles: []string{filepath.Join("/etc/*/*"), filepath.Join("/var/log/*.txt")},
			skipMap: map[string]bool{
				filepath.Join("/etc/foo"):         false,
				filepath.Join("/etc/foo/bar"):     true,
				filepath.Join("/var/log/bar.txt"): true,
			},
		},
		{
			skipFiles: []string{filepath.Join(`[^etc`)}, // filepath.Match returns ErrBadPattern
			skipMap: map[string]bool{
				filepath.Join("/etc/foo"):     false,
				filepath.Join("/etc/foo/bar"): false,
			},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			w := newWalker(tc.skipFiles, nil, false)
			for file, skipResult := range tc.skipMap {
				assert.Equal(t, skipResult, w.shouldSkipFile(file), fmt.Sprintf("skipFiles: %s, file: %s", tc.skipFiles, file))
			}
		})
	}
}

func Test_shouldSkipDir(t *testing.T) {
	if runtime.GOOS == os.Windows {
		t.Skip("glob paths are not supported on Windows")
	}

	testCases := []struct {
		skipDirs []string
		skipMap  map[string]bool
	}{
		{
			skipDirs: nil,
			skipMap: map[string]bool{
				".git":    true,  // AppDir
				"proc":    true,  // SystemDir
				"foo.bar": false, // random directory
			},
		},
		{
			skipDirs: []string{filepath.Join("/*")},
			skipMap: map[string]bool{
				filepath.Join("/etc"):         true,
				filepath.Join("/etc/foo/bar"): false,
			},
		},
		{
			skipDirs: []string{filepath.Join("/etc/*/*")},
			skipMap: map[string]bool{
				filepath.Join("/etc/foo"):     false,
				filepath.Join("/etc/foo/bar"): true,
			},
		},
		{
			skipDirs: []string{filepath.Join("/etc/*/*"), filepath.Join("/var/log/*")},
			skipMap: map[string]bool{
				filepath.Join("/etc/foo"):     false,
				filepath.Join("/etc/foo/bar"): true,
				filepath.Join("/var/log/bar"): true,
			},
		},
		{
			skipDirs: []string{filepath.Join(`[^etc`)}, // filepath.Match returns ErrBadPattern
			skipMap: map[string]bool{
				filepath.Join("/etc/foo"):     false,
				filepath.Join("/etc/foo/bar"): false,
			},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			w := newWalker(nil, tc.skipDirs, false)
			for dir, skipResult := range tc.skipMap {
				assert.Equal(t, skipResult, w.shouldSkipDir(dir), fmt.Sprintf("skipDirs: %s, dir: %s", tc.skipDirs, dir))
			}
		})
	}
}
