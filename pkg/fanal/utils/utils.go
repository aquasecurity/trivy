package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	PathSeparator = fmt.Sprintf("%c", os.PathSeparator)
)

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	return cacheDir
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func IsCommandAvailable(name string) bool {
	if _, err := exec.LookPath(name); err != nil {
		return false
	}
	return true
}

func IsGzip(f *bufio.Reader) bool {
	buf, err := f.Peek(3)
	if err != nil {
		return false
	}
	return buf[0] == 0x1F && buf[1] == 0x8B && buf[2] == 0x8
}

func Keys(m map[string]struct{}) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func IsExecutable(fileInfo os.FileInfo) bool {
	// For Windows
	if filepath.Ext(fileInfo.Name()) == ".exe" {
		return true
	}

	mode := fileInfo.Mode()
	if !mode.IsRegular() {
		return false
	}

	// Check unpackaged file
	if mode.Perm()&0111 != 0 {
		return true
	}
	return false
}

func IsBinary(content xio.ReadSeekerAt, fileSize int64) (bool, error) {
	headSize := int(math.Min(float64(fileSize), 300))
	head := make([]byte, headSize)
	if _, err := content.Read(head); err != nil {
		return false, err
	}
	if _, err := content.Seek(0, io.SeekStart); err != nil {
		return false, err
	}

	// cf. https://github.com/file/file/blob/f2a6e7cb7db9b5fd86100403df6b2f830c7f22ba/src/encoding.c#L151-L228
	for _, b := range head {
		if b < 7 || b == 11 || (13 < b && b < 27) || (27 < b && b < 0x20) || b == 0x7f {
			return true, nil
		}
	}

	return false, nil
}

func CleanSkipPaths(skipPaths []string) []string {
	return lo.Map(skipPaths, func(skipPath string, index int) string {
		skipPath = filepath.ToSlash(filepath.Clean(skipPath))
		return strings.TrimLeft(skipPath, "/")
	})
}

func SkipPath(path string, skipPaths []string) bool {
	path = strings.TrimLeft(path, "/")

	// skip files
	for _, pattern := range skipPaths {
		match, err := doublestar.Match(pattern, path)
		if err != nil {
			return false // return early if bad pattern
		} else if match {
			log.Debug("Skipping path", log.String("path", path))
			return true
		}
	}
	return false
}

func OnlyPath(path string, onlyPaths []string) bool {
	if len(onlyPaths) == 0 {
		return false
	}

	if path == "" || path == "." {
		return false
	}

	path = strings.TrimLeft(path, "/")

	for _, pattern := range onlyPaths {
		if strings.HasPrefix(pattern, path+"/") {
			return false
		}
		match, err := doublestar.Match(pattern, path)
		if err != nil {
			return false // return early if bad pattern
		} else if match {
			return false
		}
	}
	log.Debug("Skipping path", log.String("path", path))
	return true
}

func ExtractPrintableBytes(content xio.ReadSeekerAt) ([]byte, error) {
	const minLength = 4 // Minimum length of strings to extract
	var result []byte
	currentPrintableLine := new(bytes.Buffer)

	current := make([]byte, 1) // buffer for 1 byte reading

	for {
		if n, err := content.Read(current); err == io.EOF {
			break
		} else if n != 1 {
			continue
		} else if err != nil {
			return nil, xerrors.Errorf("failed to read a byte: %w", err)
		}
		if unicode.IsPrint(rune(current[0])) {
			_ = currentPrintableLine.WriteByte(current[0])
			continue
		}
		if currentPrintableLine.Len() > minLength {
			// add a newline between printable lines to separate them
			_ = currentPrintableLine.WriteByte('\n')
			result = append(result, currentPrintableLine.Bytes()...)
		}
		currentPrintableLine.Reset()
	}
	if currentPrintableLine.Len() > minLength {
		// add a newline between printable lines to separate them
		_ = currentPrintableLine.WriteByte('\n')
		result = append(result, currentPrintableLine.Bytes()...)
	}
	return result, nil
}
