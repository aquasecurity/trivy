package bundler

import (
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"os"
	"path"
	"testing"
)

func TestParse(t *testing.T){
	vectors := []struct {
		file    string // Test input file
		libraries []types.Library
	}{
		{
			file:    "testdata/Gemfile_normal.lock",
			libraries: BundlerNormal,
		},
		{
			file:    "testdata/Gemfile_rails.lock",
			libraries: BundlerRails,
		},
		{
			file:    "testdata/Gemfile_many.lock",
			libraries: BundlerMany,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			libList, err := Parse(f)
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}

			if len(libList) != len(v.libraries) {
				t.Fatalf("lib length: got %v, want %v", len(libList), len(v.libraries))
			}

			for i, got := range libList{
				want := v.libraries[i]
				if want.Name != got.Name {
					t.Errorf("%d: Name: got %s, want %s", i, got.Name, want.Name)
				}
				if want.Version != got.Version {
					t.Errorf("%d: Version: got %s, want %s", i, got.Version, want.Version)
				}
			}
		})
	}
}
