package walker

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_shouldSkipFile(t *testing.T) {
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
			skipFiles: []string{filepath.Join("**/*.txt")},
			skipMap: map[string]bool{
				filepath.Join("/etc/foo"):         false,
				filepath.Join("/etc/foo/bar"):     false,
				filepath.Join("/var/log/bar.txt"): true,
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
			w := newWalker(tc.skipFiles, nil, nil)
			for file, skipResult := range tc.skipMap {
				assert.Equal(t, skipResult, w.shouldSkipFile(filepath.ToSlash(filepath.Clean(file))), fmt.Sprintf("skipFiles: %s, file: %s", tc.skipFiles, file))
			}
		})
	}
}

func Test_shouldSkipDir(t *testing.T) {
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
		{
			skipDirs: []string{"**/.terraform"},
			skipMap: map[string]bool{
				".terraform":              true,
				"test/foo/bar/.terraform": true,
			},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			w := newWalker(nil, tc.skipDirs, nil)
			for dir, skipResult := range tc.skipMap {
				assert.Equal(t, skipResult, w.shouldSkipDir(filepath.ToSlash(filepath.Clean(dir))), fmt.Sprintf("skipDirs: %s, dir: %s", tc.skipDirs, dir))
			}
		})
	}
}

func Test_onlyDir(t *testing.T) {
	testCases := []struct {
		skipDirs []string
		onlyDirs []string
		skipMap  map[string][2]bool
	}{
		{
			skipDirs: nil,
			onlyDirs: []string{"/etc/**"},
			skipMap: map[string][2]bool{
				"/etc/foo/bar": {false, false},
				"/var/log/bar": {true, true},
			},
		},
		{
			skipDirs: nil,
			onlyDirs: []string{"/**"},
			skipMap: map[string][2]bool{
				"/foo":         {false, false},
				"/etc/foo":     {false, false},
				"/var/log/bar": {false, false},
			},
		},
		{
			skipDirs: nil,
			onlyDirs: []string{"/*"},
			skipMap: map[string][2]bool{
				"/foo":         {false, false},
				"/etc/foo":     {false, false},
				"/etc/foo/bar": {true, false},
			},
		},
		{
			skipDirs: nil,
			onlyDirs: []string{"/etc/foo/*"},
			skipMap: map[string][2]bool{
				"/etc/foo/bar":      {true, false},
				"/etc/foo2/bar":     {true, false},
				"/var/etc/foo2/bar": {true, true},
			},
		},
		{
			onlyDirs: []string{"/*/bar"},
			skipMap: map[string][2]bool{
				"/etc/bar/bar":     {false, false},
				"/etc/foo/bar":     {true, false},
				"/etc/bar/foo":     {false, false},
				"/etc/foo/bar/foo": {true, false},
			},
		},
		{
			onlyDirs: []string{"**/bar"},
			skipMap: map[string][2]bool{
				"/etc/bar/bar":     {false, false},
				"/etc/foo/bar":     {true, false},
				"/etc/bar/foo":     {false, false},
				"/etc/foo/bar/foo": {false, false},
			},
		},
		{
			onlyDirs: []string{"**/foo/*/bar"},
			skipMap: map[string][2]bool{
				"/foo/foo/bar/bar": {false, false},
				"/etc/foo/bar":     {true, false},
				"/etc/bar/foo":     {true, false},
				"/etc/foo/bar/bar": {true, false},
			},
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			w := newWalker(nil, tc.skipDirs, tc.onlyDirs)
			for file, skipResult := range tc.skipMap {
				// todo: add check on skip dir
				assert.Equal(t, skipResult[0], w.shouldSkipFile(filepath.ToSlash(filepath.Clean(file))), fmt.Sprintf("skipDirs: %s, dir: %s", tc.skipDirs, file))
				assert.Equal(t, skipResult[1], w.shouldSkipDir(filepath.ToSlash(filepath.Clean(file))), fmt.Sprintf("skipDirs: %s, dir: %s", tc.skipDirs, file))
			}
		})
	}
}
