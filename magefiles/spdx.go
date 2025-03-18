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
	exceptionFileName = "exceptions.json"
	exceptionDir      = "./pkg/licensing/expression"
	exceptionURL      = "https://spdx.org/licenses/exceptions.json"
)

type Exceptions struct {
	Exceptions []Exception `json:"exceptions"`
}

type Exception struct {
	ID string `json:"licenseExceptionId"`
}

func main() {
	if err := run(); err != nil {
		log.Fatal("Fatal error", log.Err(err))
	}

}

// run downloads exceptions.json file, takes only IDs and saves into `expression` package.
func run() error {
	tmpDir, err := downloader.DownloadToTempDir(context.Background(), exceptionURL, downloader.Options{})
	if err != nil {
		return xerrors.Errorf("unable to download exceptions.json file: %w", err)
	}
	tmpFile, err := os.ReadFile(filepath.Join(tmpDir, exceptionFileName))
	if err != nil {
		return xerrors.Errorf("unable to read exceptions.json file: %w", err)
	}

	exceptions := Exceptions{}
	if err = json.Unmarshal(tmpFile, &exceptions); err != nil {
		return xerrors.Errorf("unable to unmarshal exceptions.json file: %w", err)
	}

	exs := lo.Map(exceptions.Exceptions, func(ex Exception, _ int) string {
		return ex.ID
	})
	sort.Strings(exs)

	exceptionFile := filepath.Join(exceptionDir, exceptionFileName)
	f, err := os.Create(exceptionFile)
	if err != nil {
		return xerrors.Errorf("unable to create file %s: %w", exceptionFile, err)
	}
	defer f.Close()

	e, err := json.Marshal(exs)
	if err != nil {
		return xerrors.Errorf("unable to marshal exceptions list: %w", err)
	}

	if _, err = f.Write(e); err != nil {
		return xerrors.Errorf("unable to write exceptions list: %w", err)
	}

	return nil
}
