package walker

import (
	"errors"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-multierror"
	lru "github.com/hashicorp/golang-lru"
	"github.com/masahiro331/go-disk"
	"github.com/masahiro331/go-disk/types"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/filesystem"
	"github.com/aquasecurity/trivy/pkg/log"
)

const cacheSize = 2048

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

type VM struct {
	walker
	threshold int64
	analyzeFn WalkFunc
}

func NewVM(skipFiles, skipDirs []string, slow bool) VM {
	threshold := defaultSizeThreshold
	if slow {
		threshold = slowSizeThreshold
	}

	return VM{
		walker:    newWalker(skipFiles, skipDirs, slow),
		threshold: threshold,
	}
}

func (w *VM) Walk(vreader *io.SectionReader, root string, fn WalkFunc) error {
	// This function will be called on each file.
	w.analyzeFn = fn

	driver, err := disk.NewDriver(vreader)
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

		// Walk each partition
		if err = w.diskWalk(root, partition); err != nil {
			log.Logger.Warnf("Partition error: %s", err.Error())
		}
	}
	return nil
}

// Inject disk partitioning processes from externally with diskWalk.
func (w *VM) diskWalk(root string, partition types.Partition) error {
	if partition.Bootable() {
		return nil
	}

	log.Logger.Debugf("Found partition: %s", partition.Name())
	if !slices.Contains(requiredDiskName, partition.Name()) {
		return nil
	}

	sr := partition.GetSectionReader()
	var (
		errs, err error
		f         fs.FS
	)

	// Initialize LRU cache for filesystem walking
	lruCache, err := lru.New(cacheSize)
	if err != nil {
		return xerrors.Errorf("failed to create a LRU cache: %w", err)
	}
	defer lruCache.Purge()

	for _, fsys := range filesystem.Filesystems {
		// TODO: implement LVM handler
		f, err = fsys.New(sr, lruCache)
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
		return xerrors.New("unable to detect filesystem")
	}
	err = fs.WalkDir(f, root, func(path string, d fs.DirEntry, err error) error {
		// Walk filesystem
		return w.fsWalk(f, path, d, err)
	})
	if err != nil {
		return xerrors.Errorf("filesystem walk error: %w", err)
	}
	return nil
}

func (w *VM) fsWalk(fsys fs.FS, path string, d fs.DirEntry, err error) error {
	if err != nil {
		return xerrors.Errorf("fs.Walk error: %w", err)
	}
	fi, err := d.Info()
	if err != nil {
		return xerrors.Errorf("dir entry info error: %w", err)
	}
	pathName := strings.TrimPrefix(filepath.Clean(path), "/")
	if fi.IsDir() {
		if w.shouldSkipDir(pathName) {
			return filepath.SkipDir
		}
		return nil
	} else if !fi.Mode().IsRegular() {
		return nil
	} else if w.shouldSkipFile(pathName) {
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

	cvf := newCachedVMFile(fsys, pathName, w.threshold)
	defer cvf.Clean()

	if err = w.analyzeFn(path, fi, cvf.Open); err != nil {
		return xerrors.Errorf("failed to analyze file: %w", err)
	}
	return nil
}

type cachedVMFile struct {
	fs        fs.FS
	filePath  string
	threshold int64

	cf *cachedFile
}

func newCachedVMFile(fsys fs.FS, filePath string, threshold int64) *cachedVMFile {
	return &cachedVMFile{fs: fsys, filePath: filePath, threshold: threshold}
}

func (cvf *cachedVMFile) Open() (dio.ReadSeekCloserAt, error) {
	if cvf.cf != nil {
		return cvf.cf.Open()
	}

	f, err := cvf.fs.Open(cvf.filePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, xerrors.Errorf("file stat error: %w", err)
	}

	cvf.cf = newCachedFile(fi.Size(), f, cvf.threshold)
	return cvf.cf.Open()
}

func (cvf *cachedVMFile) Clean() error {
	if cvf.cf == nil {
		return nil
	}
	return cvf.cf.Clean()
}
