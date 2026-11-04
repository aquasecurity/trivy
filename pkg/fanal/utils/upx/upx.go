package upx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	MaxDecompressRatio = 10
	DefaultTimeout     = 30 * time.Second
	FindingNote        = "[UPX compressed binary decompressed for scanning]"
	CustomResourceType = "upx"
)

var (
	lookPathOnce sync.Once
	hasUPXBinary bool
)

func HasUPX() bool {
	lookPathOnce.Do(func() {
		_, err := exec.LookPath("upx")
		hasUPXBinary = (err == nil)
	})
	return hasUPXBinary
}

// IsUPXMagic checks if the content contains the "UPX!" signature.
func IsUPXMagic(content xio.ReadSeekerAt) (bool, error) {
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	// Read up to first 4KB to check for UPX! magic bytes
	buf := make([]byte, 4096)
	n, err := content.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	_, _ = content.Seek(0, io.SeekStart)
	return bytes.Contains(buf[:n], []byte("UPX!")), nil
}

// getUncompressedSizeFromListing runs `upx -l <packedFile>` and parses the uncompressed file size
func getUncompressedSizeFromListing(ctx context.Context, packedFile string) (int64, error) {
	cmd := exec.CommandContext(ctx, "upx", "-l", packedFile)
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	// Expected output lines like:
	//         File size         Ratio      Format      Name
	//    --------------------   ------   -----------   -----------
	//    2597807 ->   1460364   56.22%   linux/amd64   packed_bin
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "->") {
			parts := strings.Split(line, "->")
			if len(parts) >= 2 {
				origSizeStr := strings.TrimSpace(parts[0])
				origSize, parseErr := strconv.ParseInt(origSizeStr, 10, 64)
				if parseErr == nil && origSize > 0 {
					return origSize, nil
				}
			}
		}
	}
	return 0, errors.New("unable to determine uncompressed size from upx -l")
}

// Decompress decompresses a UPX-compressed binary if detected.
// It checks UPX magic bytes, runs `upx -t`, checks uncompressed size against the 10x limit,
// and decompresses with `upx -d -o` into a temp directory.
func Decompress(ctx context.Context, content xio.ReadSeekerAt, originalSize int64) (xio.ReadSeekCloserAt, func(), error) {
	if !HasUPX() {
		return nil, nil, nil
	}

	isUPX, err := IsUPXMagic(content)
	if !isUPX || err != nil {
		return nil, nil, nil
	}

	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return nil, nil, xerrors.Errorf("seek error: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "upx-decomp-*")
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to create temp dir: %w", err)
	}
	cleanupDir := func() {
		_ = os.RemoveAll(tempDir)
	}

	packedFile := filepath.Join(tempDir, "packed")
	f, err := os.OpenFile(packedFile, os.O_CREATE|os.O_WRONLY, 0700)
	if err != nil {
		cleanupDir()
		return nil, nil, xerrors.Errorf("failed to create packed file: %w", err)
	}

	written, err := io.Copy(f, content)
	_ = f.Close()
	// Restore reader position
	_, _ = content.Seek(0, io.SeekStart)

	if err != nil {
		cleanupDir()
		return nil, nil, xerrors.Errorf("failed to copy content: %w", err)
	}

	if written == 0 {
		cleanupDir()
		return nil, nil, nil
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	// 1. Run `upx -t`
	cmdTest := exec.CommandContext(ctxTimeout, "upx", "-t", packedFile)
	if err := cmdTest.Run(); err != nil {
		// Not a valid UPX packed file or test failed
		cleanupDir()
		return nil, nil, nil
	}

	// Pre-check uncompressed size via `upx -l` before decompressing
	if uncompressedSize, err := getUncompressedSizeFromListing(ctxTimeout, packedFile); err == nil {
		if uncompressedSize > written*MaxDecompressRatio {
			cleanupDir()
			log.Warn("UPX decompressed size exceeds maximum ratio (10x compressed size), skipping",
				log.Int64("compressed", written), log.Int64("decompressed", uncompressedSize))
			return nil, nil, errors.New("decompressed size exceeds 10x ratio limit")
		}
	}

	// 2. Run `upx -d -o <unpacked>`
	unpackedFile := filepath.Join(tempDir, "unpacked")
	cmdDecompress := exec.CommandContext(ctxTimeout, "upx", "-d", "-o", unpackedFile, packedFile)
	if out, err := cmdDecompress.CombinedOutput(); err != nil {
		log.Debug("Failed to decompress UPX binary", log.Err(err), log.String("output", string(out)))
		cleanupDir()
		return nil, nil, nil
	}

	unpackedInfo, err := os.Stat(unpackedFile)
	if err != nil {
		cleanupDir()
		return nil, nil, xerrors.Errorf("failed to stat decompressed file: %w", err)
	}

	// Secondary check 10x size ratio to avoid decompression bombs
	if unpackedInfo.Size() > written*MaxDecompressRatio {
		cleanupDir()
		log.Warn("UPX decompressed size exceeds maximum ratio (10x compressed size), skipping",
			log.Int64("compressed", written), log.Int64("decompressed", unpackedInfo.Size()))
		return nil, nil, errors.New("decompressed size exceeds 10x ratio limit")
	}

	decompressedF, err := os.Open(unpackedFile)
	if err != nil {
		cleanupDir()
		return nil, nil, xerrors.Errorf("failed to open decompressed file: %w", err)
	}

	cleanup := func() {
		_ = decompressedF.Close()
		cleanupDir()
	}

	return decompressedF, cleanup, nil
}
