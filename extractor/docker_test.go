package extractor

import (
	"os"
	"path"
	"reflect"
	"testing"
)

func TestExtractFromFile(t *testing.T) {
	vectors := []struct {
		file      string   // Test input file
		filenames []string // Target files
		fileMap   FileMap  // Expected output
		err       error    // Expected error to occur
	}{
		{
			file:      "testdata/image1.tar",
			filenames: []string{"var/foo", "etc/test/bar"},
			fileMap:   FileMap{"etc/test/bar": []byte("bar\n")},
			err:       nil,
		},
		{
			file:      "testdata/image2.tar",
			filenames: []string{"home/app/Gemfile", "home/app2/Gemfile"},
			fileMap:   FileMap{"home/app2/Gemfile": []byte("gem")},
			err:       nil,
		},
		{
			file:      "testdata/image3.tar",
			filenames: []string{"home/app/Gemfile", "home/app2/Pipfile", "home/app/Pipfile"},
			fileMap:   FileMap{"home/app/Pipfile": []byte("pip")},
			err:       nil,
		},
		{
			file:      "testdata/image4.tar",
			filenames: []string{".abc", ".def", "foo/.abc", "foo/.def", ".foo/.abc"},
			fileMap: FileMap{
				".def":     []byte("def"),
				"foo/.abc": []byte("abc"),
			},
			err: nil,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			defer f.Close()

			d := DockerExtractor{}
			fm, err := d.ExtractFromFile(nil, f, v.filenames)
			if v.err != err {
				t.Errorf("err: got %v, want %v", v.err, err)
			}
			if !reflect.DeepEqual(fm, v.fileMap) {
				t.Errorf("FilesMap: got %v, want %v", fm, v.fileMap)
			}
		})
	}
}

func TestExtractFiles(t *testing.T) {
	vectors := []struct {
		file      string   // Test input file
		filenames []string // Target files
		fileMap   FileMap  // Expected output
		opqDirs   opqDirs  // Expected output
		err       error    // Expected error to occur
	}{
		{
			file:      "testdata/normal.tar",
			filenames: []string{"var/foo"},
			fileMap:   FileMap{"var/foo": []byte{}},
			opqDirs:   []string{},
			err:       nil,
		},
		{
			file:      "testdata/opq.tar",
			filenames: []string{"var/foo"},
			fileMap: FileMap{
				"var/.wh.foo": []byte{},
			},
			opqDirs: []string{"etc/test"},
			err:     nil,
		},
		{
			file:      "testdata/opq2.tar",
			filenames: []string{"var/foo", "etc/test/bar"},
			fileMap: FileMap{
				"etc/test/bar": []byte("bar\n"),
				"var/.wh.foo":  []byte{},
			},
			opqDirs: []string{"etc/test"},
			err:     nil,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			defer f.Close()

			d := DockerExtractor{}
			fm, opqDirs, err := d.ExtractFiles(f, v.filenames)
			if v.err != err {
				t.Errorf("err: got %v, want %v", v.err, err)
			}
			if !reflect.DeepEqual(opqDirs, v.opqDirs) {
				t.Errorf("opqDirs: got %v, want %v", opqDirs, v.opqDirs)
			}
			if !reflect.DeepEqual(fm, v.fileMap) {
				t.Errorf("FilesMap: got %v, want %v", fm, v.fileMap)
			}
		})
	}
}
