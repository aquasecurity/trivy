package utils

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/knqyf263/trivy/pkg/log"
	"golang.org/x/xerrors"
)

var cacheDir string

func DefaultCacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "trivy")
}

func CacheDir() string {
	return cacheDir
}

func SetCacheDir(dir string) {
	cacheDir = dir
}

func FileWalk(root string, targetFiles map[string]struct{}, walkFn func(r io.Reader, path string) error) error {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return xerrors.Errorf("error in filepath rel: %w", err)
		}

		if _, ok := targetFiles[rel]; !ok {
			return nil
		}

		if info.Size() == 0 {
			log.Logger.Debugf("invalid size: %s", path)
			return nil
		}

		f, err := os.Open(path)
		defer f.Close()
		if err != nil {
			return xerrors.Errorf("failed to open file: %w", err)
		}

		if err = walkFn(f, path); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in file walk: %w", err)
	}
	return nil
}

func IsCommandAvailable(name string) bool {
	cmd := exec.Command(name, "--help")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func Exec(command string, args []string) (string, error) {
	cmd := exec.Command(command, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		log.Logger.Debug(stderrBuf.String())
		return "", xerrors.Errorf("failed to exec: %w", err)
	}
	return stdoutBuf.String(), nil
}

func FilterTargets(prefixPath string, targets map[string]struct{}) (map[string]struct{}, error) {
	filtered := map[string]struct{}{}
	for filename := range targets {
		if strings.HasPrefix(filename, prefixPath) {
			rel, err := filepath.Rel(prefixPath, filename)
			if err != nil {
				return nil, xerrors.Errorf("error in filepath rel: %w", err)
			}
			filtered[rel] = struct{}{}
		}
	}
	return filtered, nil
}
