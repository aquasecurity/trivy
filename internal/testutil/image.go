package testutil

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/image/name"
)

var (
	testImages   string
	testVMImages string
)

func init() {
	_, b, _, _ := runtime.Caller(0)
	currentDir := filepath.Dir(b)
	f, err := os.Open(filepath.Join(currentDir, "..", "..", "integration", "testimages.ini"))
	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}
		parts := strings.SplitN(scanner.Text(), "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch key {
			case "TEST_IMAGES":
				testImages = value
			case "TEST_VM_IMAGES":
				testVMImages = value
			}
		}
	}
	if err = scanner.Err(); err != nil {
		panic(err)
	}
}

func ImageName(subpath, tag, digest string) string {
	return imageName(testImages, subpath, tag, digest)
}

func VMImageName(subpath, tag, digest string) string {
	return imageName(testVMImages, subpath, tag, digest)
}

func imageName(img, subpath, tag, digest string) string {
	if subpath != "" {
		img = fmt.Sprintf("%s/%s", img, subpath)
	}
	if tag != "" {
		img = fmt.Sprintf("%s:%s", img, tag)
	}
	if digest != "" {
		img = fmt.Sprintf("%s@%s", img, digest)
	}
	return img
}

// MustParseReference parses a string into a Reference and fails the test if there's an error
func MustParseReference(t *testing.T, s string) name.Reference {
	t.Helper()
	ref, err := name.ParseReference(s)
	require.NoError(t, err)
	return ref
}
