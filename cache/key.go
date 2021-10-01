package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/fanal/artifact"

	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/config"
)

func CalcKey(id string, analyzerVersions, hookVersions map[string]int, artifactOpt artifact.Option, scannerOpt config.ScannerOption) (string, error) {
	// Sort options for consistent results
	artifactOpt.Sort()
	scannerOpt.Sort()

	h := sha256.New()

	// Write ID, analyzer/hook versions, and skipped files/dirs
	keyBase := struct {
		ID               string
		AnalyzerVersions map[string]int
		HookVersions     map[string]int
		SkipFiles        []string
		SkipDirs         []string
	}{id, analyzerVersions, hookVersions, artifactOpt.SkipFiles, artifactOpt.SkipDirs}

	if err := json.NewEncoder(h).Encode(keyBase); err != nil {
		return "", xerrors.Errorf("json encode error: %w", err)
	}

	// Write policy and data contents
	for _, paths := range [][]string{scannerOpt.PolicyPaths, scannerOpt.DataPaths} {
		for _, p := range paths {
			s, err := dirhash.HashDir(p, "", dirhash.DefaultHash)
			if err != nil {
				return "", xerrors.Errorf("hash dir (%s): %w", p, err)
			}

			if _, err = h.Write([]byte(s)); err != nil {
				return "", xerrors.Errorf("sha256 write error: %w", err)
			}
		}
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
