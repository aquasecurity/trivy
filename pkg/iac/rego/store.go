package rego

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/storage"
)

// initialize a store populated with OPA data files found in dataPaths
func initStore(dataFS fs.FS, dataPaths, namespaces []string) (storage.Store, error) {
	// FilteredPaths will recursively find all file paths that contain a valid document
	// extension from the given list of data paths.
	allDocumentPaths, _ := loader.FilteredPathsFS(dataFS, dataPaths, func(abspath string, info os.FileInfo, depth int) bool {
		if info.IsDir() {
			return false // filter in, include
		}
		ext := strings.ToLower(filepath.Ext(info.Name()))
		for _, filter := range []string{
			".yaml",
			".yml",
			".json",
		} {
			if filter == ext {
				return false // filter in, include
			}
		}
		return true // filter out, exclude
	})

	documents, err := loader.NewFileLoader().WithFS(dataFS).All(allDocumentPaths)
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
