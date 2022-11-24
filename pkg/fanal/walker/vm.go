package walker

import (
	"bytes"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/masahiro331/go-disk"
	"github.com/masahiro331/go-disk/types"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/filesystem"
	"github.com/aquasecurity/trivy/pkg/log"
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

var (
	ErrBootableOnlyDisk = xerrors.New("the disk bootable partition only error")
)

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

	bootableOnly := true
	for {
		partition, err := driver.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return xerrors.Errorf("failed to next disk error: %w", err)
		}

		// skip boot partition
		if partition.Bootable() {
			continue
		}

		// skip empty partition
		if bytes.Equal(partition.GetType(), []byte{0x00}) {
			continue
		}
		bootableOnly = false

		// Walk each partition
		if err = w.diskWalk(root, partition); err != nil {
			log.Logger.Warnf("Partition error: %s", err.Error())
		}
	}
	if bootableOnly {
		return ErrBootableOnlyDisk
	}
	return nil
}

// Inject disk partitioning processes from externally with diskWalk.
func (w *VM) diskWalk(root string, partition types.Partition) error {

	log.Logger.Debugf("Found partition: %s", partition.Name())
	if !slices.Contains(requiredDiskName, partition.Name()) {
		return nil
	}

	sr := partition.GetSectionReader()

	// Trivy does not support LVM scanning, workaround is to detect LVM signature and scan skip.
	foundLVM, err := w.detectLVM(sr)
	if err != nil {
		return xerrors.Errorf("detect lvm error: %w", err)
	}
	if foundLVM {
		log.Logger.Errorf("VM scan does not support lvm partition: skip scan partition: %s.img", partition.Name())
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

func (w *VM) detectLVM(sr io.SectionReader) (bool, error) {
	buf := make([]byte, 512)
	_, err := sr.ReadAt(buf, 512)
	if err != nil {
		return false, xerrors.Errorf("read header block error: %w", err)
	}
	_, err = sr.Seek(0, io.SeekStart)
	if err != nil {
		return false, xerrors.Errorf("seek start offset error: %w", err)
	}

	// LABELONE is LVM signature
	if string(buf[:8]) == "LABELONE" {
		return true, nil
	}
	return false, nil
}
