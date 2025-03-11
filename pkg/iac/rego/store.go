package rego

import (
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/storage"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

// initialize a store populated with OPA data files found in dataPaths
func initStore(dataFS fs.FS, dataPaths, namespaces []string) (storage.Store, error) {
	dataFiles := set.New[string]()

	// The virtual file system uses a slash ('/') as a path separator,
	// but OPA uses the filepath package, which is OS-dependent.
	// Therefore, we need to collect all the paths ourselves and pass them to OPA.
	for _, root := range dataPaths {
		if err := fs.WalkDir(dataFS, root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}

			if isDataFile(path) {
				dataFiles.Append(path)
			}
			return nil
		}); err != nil {
			log.Error("Failed to collect data file paths", log.String("root", root), log.Err(err))
		}
	}

	documents, err := loader.NewFileLoader().WithFS(dataFS).All(dataFiles.Items())
	if err != nil {
		return nil, fmt.Errorf("load documents: %w", err)
	}

	// pass all namespaces so that rego rule can refer to namespaces as data.namespaces
	documents.Documents["namespaces"] = namespaces

	store, err := documents.Store()
	if err != nil {
		return nil, fmt.Errorf("get documents store: %w", err)
	}
	return store, nil
}

func isDataFile(filePath string) bool {
	return slices.Contains([]string{
		".yaml",
		".yml",
		".json",
	}, strings.ToLower(path.Ext(filePath)))
}
