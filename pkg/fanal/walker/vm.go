package walker

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/masahiro331/go-disk"
	"github.com/masahiro331/go-disk/types"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/filesystem"
	"github.com/aquasecurity/trivy/pkg/log"
)

type VM struct {
	walker
}

var requiredDiskName = []string{
	"Linux",    // AmazonLinux image name
	"p.lxroot", // SLES image name
	"primary",  // Common image name
	"0",        // Common image name
	"1",        // Common image name
}

func AppendPermitDiskName(s ...string) {
	requiredDiskName = append(requiredDiskName, s...)
}

func NewVM(skipFiles, skipDirs []string) VM {
	return VM{
		walker: newWalker(skipFiles, skipDirs),
	}
}

type DiskWalker func(root string, partition types.Partition, fsfn FilesystemWalkDirFunc) error
type FilesystemWalkDirFunc func(fsys fs.FS, path string, d fs.DirEntry, err error) error

func (w VM) Walk(vreader *io.SectionReader, cache vm.Cache, root string, fn WalkFunc) error {
	err := walk(root, vreader, diskWalker(cache), func(fsys fs.FS, path string, d fs.DirEntry, err error) error {
		if err != nil {
			return xerrors.Errorf("fs.Walk error: %w", err)
		}
		fi, err := d.Info()
		if err != nil {
			return xerrors.Errorf("dir entry info error: %w", err)
		}
		pathname := strings.TrimPrefix(filepath.Clean(path), "/")
		if fi.IsDir() {
			if w.shouldSkipDir(pathname) {
				return filepath.SkipDir
			}
			return nil
		} else if !fi.Mode().IsRegular() {
			return nil
		} else if w.shouldSkipFile(pathname) {
			return nil
		} else if fi.Mode()&0x1000 == 0x1000 ||
			fi.Mode()&0x2000 == 0x2000 ||
			fi.Mode()&0x6000 == 0x6000 ||
			fi.Mode()&0xA000 == 0xA000 ||
			fi.Mode()&0xc000 == 0xc000 {
			// 	0x1000:	S_IFIFO (FIFO)
			// 	0x2000:	S_IFCHR (Character device)
			// 	0x6000:	S_IFBLK (Block device)
			// 	0xA000:	S_IFLNK (Symbolic link)
			// 	0xC000:	S_IFSOCK (Socket)
			return nil
		}

		if err := fn(path, fi, w.opener(fsys, fi, path)); err != nil {
			return xerrors.Errorf("failed to analyze file: %w", err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk disk error: %w", err)
	}
	return nil
}

func walk(root string, r *io.SectionReader, dfn DiskWalker, fsfn FilesystemWalkDirFunc) error {
	driver, err := disk.NewDriver(r)
	if err != nil {
		return xerrors.Errorf("failed to new disk driver: %w", err)
	}

	for {
		partition, err := driver.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return xerrors.Errorf("failed to next disk error: %w", err)
		}

		err = dfn(root, partition, fsfn)
		if err != nil {
			log.Logger.Debugf("walk partition error: %s", err.Error())
		}
	}
	return nil
}

// Inject disk partitioning processes from externally with diskWalk.
func diskWalker(cache vm.Cache) DiskWalker {
	return func(root string, partition types.Partition, fn FilesystemWalkDirFunc) error {
		if partition.Bootable() {
			return nil
		}

		log.Logger.Debugf("found partition: %s", partition.Name())
		if !utils.StringInSlice(partition.Name(), requiredDiskName) {
			return nil
		}

		sr := partition.GetSectionReader()
		var (
			errs, err error
			f         fs.FS
		)
		for _, fsys := range filesystem.Filesystems {
			// TODO: implement LVM handler
			f, err = fsys.New(sr, cache)
			if err == nil {
				break
			}
			if errors.Is(err, filesystem.ErrInvalidHeader) {
				continue
			}
			errs = multierror.Append(errs, err)
		}
		if errs != nil {
			return errs
		}
		if f == nil {
			return xerrors.Errorf("try filesystems error: %w", errs)
		}
		err = fs.WalkDir(f, root, func(path string, d fs.DirEntry, err error) error {
			return fn(f, path, d, err)
		})
		if err != nil {
			return xerrors.Errorf("filesystem walk error: %w", err)
		}
		return nil
	}
}

func (w VM) opener(fsys fs.FS, fi os.FileInfo, pathname string) analyzer.Opener {
	return func() (dio.ReadSeekCloserAt, error) {
		// FS.Open will error if the path is from the root directory.
		path, err := filepath.Rel("/", pathname)
		if err != nil {
			return nil, xerrors.Errorf("%s relative path error: %w", pathname, err)
		}

		r, err := fsys.Open(path)
		if err != nil {
			return nil, err
		}
		f := newVMFile(fi.Size(), r)
		defer func() {
			// nolint
			_ = f.Clean()
		}()

		return f.Open()
	}
}

type vmFile struct {
	once sync.Once
	err  error

	size   int64
	reader io.Reader

	content  []byte // It will be populated if this file is small
	filePath string // It will be populated if this file is large
}

func newVMFile(size int64, r io.Reader) vmFile {
	return vmFile{
		size:   size,
		reader: r,
	}
}

// Open opens a file in the virtual machine.
// If the file size is greater than or equal to threshold, it copies the content to a temp file and opens it next time.
// If the file size is less than threshold, it opens the file once and the content will be shared so that others analyzers can use the same data.
func (o *vmFile) Open() (dio.ReadSeekCloserAt, error) {
	o.once.Do(func() {
		// When the file is large, it will be written down to a temp file.
		if o.size >= ThresholdSize {
			f, err := os.CreateTemp("", "fanal-*")
			if err != nil {
				o.err = xerrors.Errorf("failed to create the temp file: %w", err)
				return
			}

			if _, err = io.Copy(f, o.reader); err != nil {
				o.err = xerrors.Errorf("failed to copy: %w", err)
				return
			}

			o.filePath = f.Name()
		} else {
			b, err := io.ReadAll(o.reader)
			if err != nil {
				o.err = xerrors.Errorf("unable to read the file: %w", err)
				return
			}
			o.content = b
		}
	})
	if o.err != nil {
		return nil, xerrors.Errorf("failed to open: %w", o.err)
	}

	return o.open()
}

func (o *vmFile) open() (dio.ReadSeekCloserAt, error) {
	if o.filePath != "" {
		f, err := os.Open(o.filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open the temp file: %w", err)
		}
		return f, nil
	}

	return dio.NopCloser(bytes.NewReader(o.content)), nil
}

func (o *vmFile) Clean() error {
	return os.Remove(o.filePath)
}
