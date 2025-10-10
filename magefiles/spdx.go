//go:build mage_spdx

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	expressionDir = "./pkg/licensing/expression"

	exceptionFileName = "exceptions.json"
	exceptionURL      = "https://spdx.org/licenses/exceptions.json"

	licenseFileName = "licenses.json"
	licenseURL      = "https://spdx.org/licenses/licenses.json"
)

func main() {
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

// run downloads SPDX licenses and exceptions, extracts only IDs and writes flat arrays into the `expression` package.
func run() error {
	if err := updateLicenses(); err != nil {
		return err
	}
	return updateExceptions()
}

func updateExceptions() error {
	return fetchAndWrite(exceptionURL, exceptionFileName, filepath.Join(expressionDir, exceptionFileName), func(b []byte) ([]string, error) {
		var exceptions Exceptions
		if err := json.Unmarshal(b, &exceptions); err != nil {
			return nil, xerrors.Errorf("unable to unmarshal exceptions.json file: %w", err)
		}
		exs := lo.Map(exceptions.Exceptions, func(ex Exception, _ int) string { return ex.ID })
		return exs, nil
	})
}

type Licenses struct {
	Licenses []License `json:"licenses"`
}

type License struct {
	ID string `json:"licenseId"`
}

func updateLicenses() error {
	return fetchAndWrite(licenseURL, licenseFileName, filepath.Join(expressionDir, licenseFileName), func(b []byte) ([]string, error) {
		var licenses Licenses
		if err := json.Unmarshal(b, &licenses); err != nil {
			return nil, xerrors.Errorf("unable to unmarshal licenses.json file: %w", err)
		}
		ids := lo.Map(licenses.Licenses, func(l License, _ int) string { return l.ID })
		return ids, nil
	})
}

// fetchAndWrite downloads a SPDX index file, extracts IDs using extractor, sorts and writes them to destPath
func fetchAndWrite(url, tmpFileName, destPath string, extractor func([]byte) ([]string, error)) error {
	tmpDir, err := downloader.DownloadToTempDir(context.Background(), url, downloader.Options{})
	if err != nil {
		return xerrors.Errorf("unable to download %s: %w", tmpFileName, err)
	}
	tmpFile, err := os.ReadFile(filepath.Join(tmpDir, tmpFileName))
	if err != nil {
		return xerrors.Errorf("unable to read %s: %w", tmpFileName, err)
	}

	ids, err := extractor(tmpFile)
	if err != nil {
		return err
	}
	sort.Strings(ids)
	return writeIDs(destPath, ids)
}

func writeIDs(path string, ids []string) error {
	f, err := os.Create(path)
	if err != nil {
		return xerrors.Errorf("unable to create file %s: %w", path, err)
	}
	defer f.Close()

	b, err := json.Marshal(ids)
	if err != nil {
		return xerrors.Errorf("unable to marshal id list: %w", err)
	}
	if _, err = f.Write(b); err != nil {
		return xerrors.Errorf("unable to write id list: %w", err)
	}
	return nil
}
