package rpm

import (
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/magefile/mage/target"
	"golang.org/x/xerrors"
)

const url = "https://mirror.openshift.com/pub/openshift-v4/amd64/dependencies/rpms/4.10-beta/socat-1.7.3.2-2.el7.x86_64.rpm"

// Fixtures downloads RPM files for unit tests
func Fixtures() error {
	_, filePath, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filePath)
	dst := filepath.Join(dir, path.Base(url))

	// Download the file only when it is needed
	if updated, err := target.Path(dst, filePath); err != nil {
		return err
	} else if !updated {
		return nil
	}
	return downloadFile(url, dst)
}

// downloadFile downloads a file from the given URL and saves it with the original filename
// TODO: move this function to a common package for Mage
func downloadFile(url, dst string) error {
	slog.Info("Downloading...", slog.String("url", url))

	// Send a GET request to the URL
	resp, err := http.Get(url)
	if err != nil {
		return xerrors.Errorf("error sending GET request: %v", err)
	}
	defer resp.Body.Close()

	// Check if the response status code is OK (200)
	if resp.StatusCode != http.StatusOK {
		return xerrors.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Create a new file with the extracted filename
	out, err := os.Create(dst)
	if err != nil {
		return xerrors.Errorf("error creating file: %v", err)
	}
	defer out.Close()

	// Copy the response body to the file
	if _, err = io.Copy(out, resp.Body); err != nil {
		return xerrors.Errorf("error writing to file: %v", err)
	}

	return nil
}
