package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/errors"
)

// Descriptor contains information about a file and
// can be used to read the file contents.
type Descriptor struct {
	url       string
	path      string
	reader    io.Reader
	closer    io.Closer
	closeOnce *sync.Once
}

// lazyFile defers reading the file until the first call of Read
type lazyFile struct {
	path string
	file *os.File
}

// newLazyFile creates a new instance of lazyFile
func newLazyFile(path string) *lazyFile {
	return &lazyFile{path: path}
}

// Read implements io.Reader. It will check if the file has been opened
// and open it if it has not before attempting to read using the file's
// read method
func (f *lazyFile) Read(b []byte) (int, error) {
	var err error

	if f.file == nil {
		if f.file, err = os.Open(f.path); err != nil {
			return 0, errors.Wrapf(err, "failed to open file %s", f.path)
		}
	}

	return f.file.Read(b)
}

// Close closes the lazy file if it has been opened using the file's
// close method
func (f *lazyFile) Close() error {
	if f.file != nil {
		return f.file.Close()
	}

	return nil
}

func newDescriptor(url, path string, reader io.Reader) *Descriptor {
	return &Descriptor{
		url:    url,
		path:   path,
		reader: reader,
	}
}

func (d *Descriptor) withCloser(closer io.Closer) *Descriptor {
	d.closer = closer
	d.closeOnce = new(sync.Once)
	return d
}

// Path returns the path of the file.
func (d *Descriptor) Path() string {
	return d.path
}

// URL returns the url of the file.
func (d *Descriptor) URL() string {
	return d.url
}

// Read will read all the contents from the file the Descriptor refers to
// into the dest writer up n bytes. Will return an io.EOF error
// if EOF is encountered before n bytes are read.
func (d *Descriptor) Read(dest io.Writer, n int64) (int64, error) {
	n, err := io.CopyN(dest, d.reader, n)
	return n, err
}

// Close the file, on some Loader implementations this might be a no-op.
// It should *always* be called regardless of file.
func (d *Descriptor) Close() error {
	var err error
	if d.closer != nil {
		d.closeOnce.Do(func() {
			err = d.closer.Close()
		})
	}
	return err
}

// DirectoryLoader defines an interface which can be used to load
// files from a directory by iterating over each one in the tree.
type DirectoryLoader interface {
	// NextFile must return io.EOF if there is no next value. The returned
	// descriptor should *always* be closed when no longer needed.
	NextFile() (*Descriptor, error)
}

type dirLoader struct {
	root  string
	files []string
	idx   int
}

// NewDirectoryLoader returns a basic DirectoryLoader implementation
// that will load files from a given root directory path.
func NewDirectoryLoader(root string) DirectoryLoader {

	if len(root) > 1 {
		// Normalize relative directories, ex "./src/bundle" -> "src/bundle"
		// We don't need an absolute path, but this makes the joined/trimmed
		// paths more uniform.
		if root[0] == '.' && root[1] == filepath.Separator {
			if len(root) == 2 {
				root = root[:1] // "./" -> "."
			} else {
				root = root[2:] // remove leading "./"
			}
		}
	}

	d := dirLoader{
		root: root,
	}
	return &d
}

// NextFile iterates to the next file in the directory tree
// and returns a file Descriptor for the file.
func (d *dirLoader) NextFile() (*Descriptor, error) {
	// build a list of all files we will iterate over and read, but only one time
	if d.files == nil {
		d.files = []string{}
		err := filepath.Walk(d.root, func(path string, info os.FileInfo, err error) error {
			if info != nil && info.Mode().IsRegular() {
				d.files = append(d.files, filepath.ToSlash(path))
			}
			return nil
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to list files")
		}
	}

	// If done reading files then just return io.EOF
	// errors for each NextFile() call
	if d.idx >= len(d.files) {
		return nil, io.EOF
	}

	fileName := d.files[d.idx]
	d.idx++
	fh := newLazyFile(fileName)

	// Trim off the root directory and return path as if chrooted
	cleanedPath := strings.TrimPrefix(fileName, d.root)
	if d.root == "." && filepath.Base(fileName) == ManifestExt {
		cleanedPath = fileName
	}

	if !strings.HasPrefix(cleanedPath, "/") {
		cleanedPath = "/" + cleanedPath
	}

	f := newDescriptor(path.Join(d.root, cleanedPath), cleanedPath, fh).withCloser(fh)
	return f, nil
}

type tarballLoader struct {
	baseURL string
	r       io.Reader
	tr      *tar.Reader
	files   []file
	idx     int
}

type file struct {
	name   string
	reader io.Reader
}

// NewTarballLoader is deprecated. Use NewTarballLoaderWithBaseURL instead.
func NewTarballLoader(r io.Reader) DirectoryLoader {
	l := tarballLoader{
		r: r,
	}
	return &l
}

// NewTarballLoaderWithBaseURL returns a new DirectoryLoader that reads
// files out of a gzipped tar archive. The file URLs will be prefixed
// with the baseURL.
func NewTarballLoaderWithBaseURL(r io.Reader, baseURL string) DirectoryLoader {
	l := tarballLoader{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		r:       r,
	}
	return &l
}

// NextFile iterates to the next file in the directory tree
// and returns a file Descriptor for the file.
func (t *tarballLoader) NextFile() (*Descriptor, error) {
	if t.tr == nil {
		gr, err := gzip.NewReader(t.r)
		if err != nil {
			return nil, errors.Wrap(err, "archive read failed")
		}

		t.tr = tar.NewReader(gr)
	}

	if t.files == nil {
		t.files = []file{}

		for {
			header, err := t.tr.Next()
			if err == io.EOF {
				break
			}

			if err != nil {
				return nil, err
			}

			// Keep iterating on the archive until we find a normal file
			if header.Typeflag == tar.TypeReg {
				f := file{name: header.Name}

				var buf bytes.Buffer
				if _, err := io.Copy(&buf, t.tr); err != nil {
					return nil, errors.Wrapf(err, "failed to copy file %s", header.Name)
				}

				f.reader = &buf

				t.files = append(t.files, f)
			}
		}
	}

	// If done reading files then just return io.EOF
	// errors for each NextFile() call
	if t.idx >= len(t.files) {
		return nil, io.EOF
	}

	f := t.files[t.idx]
	t.idx++

	return newDescriptor(path.Join(t.baseURL, f.name), f.name, f.reader), nil
}
