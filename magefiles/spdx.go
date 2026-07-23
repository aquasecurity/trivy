//go:build mage_spdx

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

const (
	expressionDir = "./pkg/licensing/expression"

	exceptionFileName = "exceptions.json"
	exceptionURL      = "https://spdx.org/licenses/exceptions.json"

	licenseFileName = "licenses.json"
	licenseURL      = "https://spdx.org/licenses/licenses.json"
)

func main() {
	log.InitLogger(false, false)
	if err := run(); err != nil {
		log.Fatal("Fatal error", log.Err(err))
	}

}

type Exceptions struct {
	Exceptions []Exception `json:"exceptions"`
}

type Exception struct {
	ID string `json:"licenseExceptionId"`
}

// run downloads SPDX licenses and exceptions and writes them into the `expression` package:
// exceptions as a flat array of IDs, and licenses as a map of ID to its normalized seeAlso URLs.
func run() error {
	if err := updateLicenses(); err != nil {
		return err
	}
	return updateExceptions()
}

func updateExceptions() error {
	b, err := fetch(exceptionURL, exceptionFileName)
	if err != nil {
		return err
	}

	var exceptions Exceptions
	if err := json.Unmarshal(b, &exceptions); err != nil {
		return xerrors.Errorf("unable to unmarshal exceptions.json file: %w", err)
	}

	exs := xslices.Map(exceptions.Exceptions, func(ex Exception) string { return ex.ID })
	sort.Strings(exs)
	return writeJSON(filepath.Join(expressionDir, exceptionFileName), exs)
}

type Licenses struct {
	Licenses []License `json:"licenses"`
}

type License struct {
	ID string `json:"licenseId"`
	// SeeAlso lists the upstream license URLs (e.g. https://www.apache.org/licenses/LICENSE-2.0).
	// Inverting these gives a URL -> SPDX-ID index for values that appear as URLs
	// (OSGi Bundle-License headers, pom <url> fallbacks).
	SeeAlso []string `json:"seeAlso"`
}

func updateLicenses() error {
	b, err := fetch(licenseURL, licenseFileName)
	if err != nil {
		return err
	}

	var licenses Licenses
	if err := json.Unmarshal(b, &licenses); err != nil {
		return xerrors.Errorf("unable to unmarshal licenses.json file: %w", err)
	}

	// result maps each SPDX license ID to its normalized seeAlso URLs. Every ID is
	// added up front (even with no URL) so the map doubles as the SPDX license ID
	// list used for validation.
	result := make(map[string][]string, len(licenses.Licenses))
	for _, l := range licenses.Licenses {
		if l.ID != "" {
			result[l.ID] = []string{}
		}
	}

	// Resolve each normalized URL to a single license ID:
	//   - the first license to reference it -> its ID
	//   - more IDs of the same only/or-later/+ family -> the smallest of them (see below)
	//   - genuinely different licenses -> "" (ambiguous; the URL is dropped)
	urlToID := make(map[string]string)
	for _, l := range licenses.Licenses {
		if l.ID == "" {
			continue
		}
		seen := set.New[string]() // dedup URLs within a single license
		for _, raw := range l.SeeAlso {
			u := licensing.NormalizeLicenseURL(raw)
			if u == "" {
				continue
			}
			if seen.Contains(u) {
				continue
			}
			seen.Append(u)

			switch existing, ok := urlToID[u]; {
			case !ok:
				urlToID[u] = l.ID
			case existing == "":
				// Already marked ambiguous; keep it dropped.
			case licenseStem(existing) == licenseStem(l.ID):
				// Same only/or-later/+ family: keep the lexicographically smallest
				// referencing ID — deterministic, and the bare base when it is in the
				// group ("GPL-3.0" < "GPL-3.0+" < "GPL-3.0-only" < ...).
				if l.ID < existing {
					urlToID[u] = l.ID
				}
			default:
				log.Warn("Dropping ambiguous license URL shared by different licenses",
					log.String("url", u), log.String("licenses", existing+", "+l.ID))
				urlToID[u] = ""
			}
		}
	}

	// Attach each resolved URL to its license. Ambiguous URLs were dropped above
	// (empty ID); every remaining ID is a real SPDX license, so it is a key in result.
	for u, id := range urlToID {
		if id == "" {
			continue
		}
		result[id] = append(result[id], u)
	}
	for id := range result {
		sort.Strings(result[id])
	}

	return writeJSON(filepath.Join(expressionDir, licenseFileName), result)
}

// licenseStem strips a trailing +, -only or -or-later suffix from an SPDX license
// ID, mapping only/or-later/+ variants to their shared base (e.g. "GPL-3.0-only"
// and "GPL-3.0+" both -> "GPL-3.0").
func licenseStem(id string) string {
	for _, suffix := range []string{"-or-later", "-only", "+"} {
		if s, ok := strings.CutSuffix(id, suffix); ok {
			return s
		}
	}
	return id
}

// fetch downloads a SPDX index file and returns its contents.
func fetch(url, tmpFileName string) ([]byte, error) {
	tmpDir, err := downloader.DownloadToTempDir(context.Background(), url, downloader.Options{})
	if err != nil {
		return nil, xerrors.Errorf("unable to download %s: %w", tmpFileName, err)
	}
	b, err := os.ReadFile(filepath.Join(tmpDir, tmpFileName))
	if err != nil {
		return nil, xerrors.Errorf("unable to read %s: %w", tmpFileName, err)
	}
	return b, nil
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return xerrors.Errorf("unable to create file %s: %w", path, err)
	}
	defer f.Close()

	b, err := json.Marshal(v)
	if err != nil {
		return xerrors.Errorf("unable to marshal %s: %w", path, err)
	}
	if _, err = f.Write(b); err != nil {
		return xerrors.Errorf("unable to write %s: %w", path, err)
	}
	return nil
}
