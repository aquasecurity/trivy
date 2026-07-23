// Package walker provides filesystem walkers for Trivy artifact scanning.
//
// appimage.go contains AppImage-specific detection (magic bytes, ELF offset
// calculation) and a thin Walk wrapper that delegates to WalkSquashFS.
// If you are adding Snap support, create snap.go alongside this file and
// call WalkSquashFS the same way — the squashfs reading logic is shared.
package walker

import (
	"debug/elf"
	"io"

	"golang.org/x/xerrors"
)

// AppImageMagic is the 3-byte identifier at offset 8 in an AppImage Type 2 file.
// AppImage Type 2 embeds a SquashFS payload starting after the ELF runtime binary.
const AppImageMagic = "AI\x02"

// AppImage walks the SquashFS filesystem embedded inside an AppImage Type 2 file.
// Detection (IsAppImage / FindSquashFSOffset) is the caller's responsibility;
// Walk receives a SectionReader already sliced to the SquashFS payload.
//
// Future squashfs-based formats (Snap, Flatpak) can follow the same pattern
// by calling WalkSquashFS directly.
type AppImage struct{}

// NewAppImage creates a new AppImage walker.
func NewAppImage() *AppImage { return &AppImage{} }

// Walk walks the SquashFS filesystem from sqfsReader.
// The second argument (root) is unused for AppImage — kept for interface
// compatibility with the VM walker.
func (w *AppImage) Walk(sqfsReader *io.SectionReader, _ string, opt Option, fn WalkFunc) error {
	return WalkSquashFS(sqfsReader, opt, fn)
}

// IsAppImage returns true if the reader contains an AppImage Type 2 file.
// It checks for the 3-byte magic "AI\x02" at byte offset 8 in the ELF header.
func IsAppImage(r io.ReaderAt) bool {
	magic := make([]byte, 3)
	if _, err := r.ReadAt(magic, 8); err != nil {
		return false
	}
	return string(magic) == AppImageMagic
}

// FindSquashFSOffset locates the byte offset of the embedded SquashFS payload
// within an AppImage by scanning ELF program- and section-header extents for
// the SquashFS superblock magic "hsqs".
func FindSquashFSOffset(r io.ReaderAt) (int64, error) {
	f, err := elf.NewFile(io.NewSectionReader(r, 0, 1<<62))
	if err != nil {
		return 0, xerrors.Errorf("failed to parse ELF header: %w", err)
	}

	var maxOffset uint64
	for _, prog := range f.Progs {
		if end := prog.Off + prog.Filesz; end > maxOffset {
			maxOffset = end
		}
	}
	for _, sect := range f.Sections {
		if end := sect.Offset + sect.Size; end > maxOffset {
			maxOffset = end
		}
	}

	// Scan forward looking for the SquashFS little-endian magic "hsqs".
	// Allow up to 4096 bytes of alignment padding after the ELF payload.
	magic := make([]byte, 4)
	for i := maxOffset; i < maxOffset+4096; i++ {
		if _, err = r.ReadAt(magic, int64(i)); err != nil {
			break
		}
		if string(magic) == "hsqs" {
			return int64(i), nil
		}
	}

	return 0, xerrors.Errorf("could not find SquashFS magic 'hsqs' after ELF payload")
}
