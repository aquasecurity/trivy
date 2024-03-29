package parser

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
)

type modulesMetadata struct {
	Modules []struct {
		Key     string `json:"Key"`
		Source  string `json:"Source"`
		Version string `json:"Version"`
		Dir     string `json:"Dir"`
	} `json:"Modules"`
}

func loadModuleMetadata(target fs.FS, fullPath string) (*modulesMetadata, string, error) {
	metadataPath := filepath.Join(fullPath, ".terraform/modules/modules.json") // nolint: gocritic

	f, err := target.Open(metadataPath)
	if err != nil {
		return nil, metadataPath, err
	}
	defer func() { _ = f.Close() }()

	var metadata modulesMetadata
	if err := json.NewDecoder(f).Decode(&metadata); err != nil {
		return nil, metadataPath, err
	}

	return &metadata, metadataPath, nil
}
