package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
)

func CalcKey(id string, analyzerVersions analyzer.Versions, hookVersions map[string]int, artifactOpt artifact.Option) (string, error) {
	// Sort options for consistent results
	artifactOpt.Sort()
	artifactOpt.MisconfScannerOption.Sort()

	h := sha256.New()

	// Write ID, analyzer/handler versions, skipped files/dirs and file patterns
	keyBase := struct {
		ID               string
		AnalyzerVersions analyzer.Versions
		HookVersions     map[string]int
		SkipFiles        []string
		SkipDirs         []string
		FilePatterns     []string `json:",omitempty"`
	}{id, analyzerVersions, hookVersions, artifactOpt.SkipFiles, artifactOpt.SkipDirs, artifactOpt.FilePatterns}

	if err := json.NewEncoder(h).Encode(keyBase); err != nil {
		return "", xerrors.Errorf("json encode error: %w", err)
	}

	// Write policy, data contents and secret config file
	paths := append(artifactOpt.MisconfScannerOption.PolicyPaths, artifactOpt.MisconfScannerOption.DataPaths...)

	// Check if the secret config exists.
	if _, err := os.Stat(artifactOpt.SecretScannerOption.ConfigPath); err == nil {
		paths = append(paths, artifactOpt.SecretScannerOption.ConfigPath)
	}

	for _, p := range paths {
		hash, err := hashContents(p)
		if err != nil {
			return "", err
		}

		if _, err := h.Write([]byte(hash)); err != nil {
			return "", xerrors.Errorf("sha256 write error: %w", err)
		}
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}

func hashContents(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", xerrors.Errorf("file %q stat error: %w", path, err)
	}

	var hash string

	if fi.IsDir() {
		hash, err = dirhash.HashDir(path, "", dirhash.DefaultHash)
		if err != nil {
			return "", xerrors.Errorf("hash dir error (%s): %w", path, err)
		}
	} else {
		hash, err = dirhash.DefaultHash([]string{filepath.Base(path)}, func(_ string) (io.ReadCloser, error) {
			return os.Open(path)
		})
		if err != nil {
			return "", xerrors.Errorf("hash file error (%s): %w", path, err)
		}
	}
	return hash, nil
}
