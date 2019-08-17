package utils

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/knqyf263/trivy/pkg/log"
	"github.com/kylelemons/godebug/pretty"
)

func touch(t *testing.T, name string) {
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, name string, content string) {
	err := ioutil.WriteFile(name, []byte(content), 0666)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFileWalk(t *testing.T) {
	if err := log.InitLogger(false); err != nil {
		t.Fatal(err)
	}
	td, err := ioutil.TempDir("", "walktest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(td)

	if err := os.MkdirAll(filepath.Join(td, "dir"), 0755); err != nil {
		t.Fatal(err)
	}
	touch(t, filepath.Join(td, "dir/foo1"))
	touch(t, filepath.Join(td, "dir/foo2"))
	write(t, filepath.Join(td, "dir/foo3"), "foo3")
	write(t, filepath.Join(td, "dir/foo4"), "foo4")

	sawDir := false
	sawFoo1 := false
	sawFoo2 := false
	sawFoo4 := false
	var contentFoo3 []byte
	walker := func(r io.Reader, path string) error {
		if strings.HasSuffix(path, "dir") {
			sawDir = true
		}
		if strings.HasSuffix(path, "foo1") {
			sawFoo1 = true
		}
		if strings.HasSuffix(path, "foo2") {
			sawFoo2 = true
		}
		if strings.HasSuffix(path, "foo3") {
			contentFoo3, err = ioutil.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
		}
		if strings.HasSuffix(path, "foo4") {
			sawFoo4 = true
		}
		return nil
	}

	targetFiles := map[string]struct{}{
		"dir/foo2": {},
		"dir/foo3": {},
	}
	err = FileWalk(td, targetFiles, walker)
	if err != nil {
		t.Fatal(err)
	}
	if sawDir {
		t.Error("directories must not be passed to walkFn")
	}
	if sawFoo1 || sawFoo4 {
		t.Error("a file not included in targetFiles must not be passed to walkFn")
	}
	if sawFoo2 {
		t.Error("an empty file must not be passed to walkFn")
	}
	if string(contentFoo3) != "foo3" {
		t.Error("The file content is wrong")
	}
}
func TestFilterTargets(t *testing.T) {
	vectors := map[string]struct {
		prefix   string
		targets  map[string]struct{} // Target files
		expected map[string]struct{}
		err      error // Expected error to occur
	}{
		"normal": {
			prefix: "dir",
			targets: map[string]struct{}{
				"dir/file1": {},
				"dir/file2": {},
				"foo/bar":   {},
			},
			expected: map[string]struct{}{
				"file1": {},
				"file2": {},
			},
			err: nil,
		},
		"other directory with the same prefix": {
			prefix: "dir",
			targets: map[string]struct{}{
				"dir/file1":  {},
				"dir2/file2": {},
			},
			expected: map[string]struct{}{
				"file1": {},
			},
			err: nil,
		},
	}

	for testName, v := range vectors {
		t.Run(testName, func(t *testing.T) {
			actual, err := FilterTargets(v.prefix, v.targets)
			if err != nil {
				t.Errorf("err: got %v, want %v", v.err, err)
			}
			if !reflect.DeepEqual(actual, v.expected) {
				t.Errorf("[%s]\n%s", testName, pretty.Compare(v.expected, actual))

			}
		})
	}
}
