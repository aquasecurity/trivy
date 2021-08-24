package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"golang.org/x/mod/sumdb/dirhash"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/config"
)

func CalcKey(id string, analyzerVersions, hookVersions map[string]int, opt *config.ScannerOption) (string, error) {
	// Sort options for consistent results
	opt.Sort()

	h := sha256.New()

	if _, err := h.Write([]byte(id)); err != nil {
		return "", xerrors.Errorf("sha256 error: %w", err)
	}

	if err := json.NewEncoder(h).Encode(analyzerVersions); err != nil {
		return "", xerrors.Errorf("json encode error: %w", err)
	}

	if err := json.NewEncoder(h).Encode(hookVersions); err != nil {
		return "", xerrors.Errorf("json encode error: %w", err)
	}

	for _, paths := range [][]string{opt.PolicyPaths, opt.DataPaths} {
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
