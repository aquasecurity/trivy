package walker

import (
	"bytes"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"github.com/masahiro331/go-disk"
	diskFs "github.com/masahiro331/go-disk/fs"
	"github.com/masahiro331/go-disk/gpt"
	"github.com/masahiro331/go-disk/mbr"
	"github.com/masahiro331/go-disk/types"
	"github.com/masahiro331/go-ext4-filesystem/ext4"
	"github.com/masahiro331/go-xfs-filesystem/xfs"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/filesystem"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var requiredDiskName = []string{
	"Linux",    // AmazonLinux image name
	"p.lxroot", // SLES image name
	"primary",  // Common image name
	"0",        // Common image name
	"1",        // Common image name
	"2",        // Common image name
	"3",        // Common image name
}

var checkFsFuncs = []diskFs.CheckFsFunc{
	ext4.Check,
	xfs.Check,
}

func AppendPermitDiskName(s ...string) {
	requiredDiskName = append(requiredDiskName, s...)
}

type VM struct {
	logger    *log.Logger
	skipFiles []string
	skipDirs  []string
	analyzeFn WalkFunc
}

func NewVM() *VM {
	return &VM{
		logger: log.WithPrefix("vm"),
	}
}

func (w *VM) Walk(vreader *io.SectionReader, root string, opt Option, fn WalkFunc) error {
	w.skipFiles = opt.SkipFiles
	w.skipDirs = append(opt.SkipDirs, defaultSkipDirs...)

	// This function will be called on each file.
	w.analyzeFn = fn

	driver, err := disk.NewDriver(vreader, checkFsFuncs...)
	if err != nil {
		return xerrors.Errorf("failed to new disk driver: %w", err)
	}

	for {
		partition, err := driver.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return xerrors.Errorf("failed to get a next partition: %w", err)
		}

		// skip boot partition
		if shouldSkip(partition) {
			continue
		}

		// Walk each partition
		if err = w.diskWalk(root, partition); err != nil {
			w.logger.Warn("Partition error", log.Err(err))
		}
	}
	return nil
}

// Inject disk partitioning processes from externally with diskWalk.
func (w *VM) diskWalk(root string, partition types.Partition) error {
	w.logger.Debug("Found partition", log.String("name", partition.Name()))

	sr := partition.GetSectionReader()

	// Trivy does not support LVM scanning. It is skipped at the moment.
	foundLVM, err := w.detectLVM(sr)
	if err != nil {
		return xerrors.Errorf("LVM detection error: %w", err)
	} else if foundLVM {
		w.logger.Error("LVM is not supported, skipping", log.String("name", partition.Name()+".img"))
		return nil
	}

	// Auto-detect filesystem such as ext4 and xfs
	fsys, clean, err := filesystem.New(sr)
	if err != nil {
		return xerrors.Errorf("filesystem error: %w", err)
	}
	defer clean()

	err = fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		// Walk filesystem
		return w.fsWalk(fsys, path, d, err)
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
	switch {
	case fi.IsDir():
		if utils.SkipPath(pathName, w.skipDirs) {
			return filepath.SkipDir
		}
		return nil
	case !fi.Mode().IsRegular():
		return nil
	case utils.SkipPath(pathName, w.skipFiles):
		return nil
	case fi.Mode()&0x1000 == 0x1000 ||
		fi.Mode()&0x2000 == 0x2000 ||
		fi.Mode()&0x6000 == 0x6000 ||
		fi.Mode()&0xA000 == 0xA000 ||
		fi.Mode()&0xc000 == 0xc000:
		// 	0x1000:	S_IFIFO (FIFO)
		// 	0x2000:	S_IFCHR (Character device)
		// 	0x6000:	S_IFBLK (Block device)
		// 	0xA000:	S_IFLNK (Symbolic link)
		// 	0xC000:	S_IFSOCK (Socket)
		return nil
	}

	cvf := newCachedVMFile(fsys, pathName)
	defer cvf.Clean()

	if err = w.analyzeFn(path, fi, cvf.Open); err != nil {
		return xerrors.Errorf("failed to analyze file: %w", err)
	}
	return nil
}

type cachedVMFile struct {
	fs       fs.FS
	filePath string

	cf *cachedFile
}

func newCachedVMFile(fsys fs.FS, filePath string) *cachedVMFile {
	return &cachedVMFile{
		fs:       fsys,
		filePath: filePath,
	}
}

func (cvf *cachedVMFile) Open() (xio.ReadSeekCloserAt, error) {
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

	cvf.cf = newCachedFile(fi.Size(), f)
	return cvf.cf.Open()
}

func (cvf *cachedVMFile) Clean() error {
	if cvf.cf == nil {
		return nil
	}
	return cvf.cf.Clean()
}

func (w *VM) detectLVM(sr io.SectionReader) (bool, error) {
	buf := make([]byte, 512)
	_, err := sr.ReadAt(buf, 512)
	if err != nil {
		return false, xerrors.Errorf("read header block error: %w", err)
	}
	_, err = sr.Seek(0, io.SeekStart)
	if err != nil {
		return false, xerrors.Errorf("seek error: %w", err)
	}

	// LABELONE is LVM signature
	if string(buf[:8]) == "LABELONE" {
		return true, nil
	}
	return false, nil
}

func shouldSkip(partition types.Partition) bool {
	// skip empty partition
	if bytes.Equal(partition.GetType(), []byte{0x00}) {
		return true
	}

	if !slices.Contains(requiredDiskName, partition.Name()) {
		return true
	}

	switch p := partition.(type) {
	case *gpt.PartitionEntry:
		return p.Bootable()
	case *mbr.Partition:
		return false
	}
	return false
}
