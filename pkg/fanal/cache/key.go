package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"

	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/xerrors"
)

func CalcKey(id string, analyzerVersions, hookVersions map[string]int, artifactOpt artifact.Option) (string, error) {
	// Sort options for consistent results
	artifactOpt.Sort()
	artifactOpt.MisconfScannerOption.Sort()

	h := sha256.New()

	// Write ID, analyzer/handler versions, skipped files/dirs and file patterns
	keyBase := struct {
		ID               string
		AnalyzerVersions map[string]int
		HookVersions     map[string]int
		SkipFiles        []string
		SkipDirs         []string
		OnlyDirs         []string
		FilePatterns     []string `json:",omitempty"`
	}{id, analyzerVersions, hookVersions, artifactOpt.SkipFiles, artifactOpt.SkipDirs, artifactOpt.OnlyDirs, artifactOpt.FilePatterns}

	if err := json.NewEncoder(h).Encode(keyBase); err != nil {
		return "", xerrors.Errorf("json encode error: %w", err)
	}

	// Write policy and data contents
	for _, paths := range [][]string{artifactOpt.MisconfScannerOption.PolicyPaths, artifactOpt.MisconfScannerOption.DataPaths} {
		for _, p := range paths {
			s, err := dirhash.HashDir(p, "", dirhash.DefaultHash)
			if err != nil {
				return "", xerrors.Errorf("hash dir error (%s): %w", p, err)
			}

			if _, err = h.Write([]byte(s)); err != nil {
				return "", xerrors.Errorf("sha256 write error: %w", err)
			}
		}
	}

	// TODO: add secret scanner option here

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
