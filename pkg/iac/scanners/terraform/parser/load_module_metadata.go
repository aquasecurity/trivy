package parser

import (
	"encoding/json"
	"io/fs"
	"path"
)

const ManifestSnapshotFile = ".terraform/modules/modules.json"

type ModulesMetadata struct {
	Modules []ModuleMetadata `json:"Modules"`
}

type ModuleMetadata struct {
	Key     string `json:"Key"`
	Source  string `json:"Source"`
	Version string `json:"Version"`
	Dir     string `json:"Dir"`
}

func loadModuleMetadata(target fs.FS, fullPath string) (*ModulesMetadata, string, error) {
	metadataPath := path.Join(fullPath, ManifestSnapshotFile)

	f, err := target.Open(metadataPath)
	if err != nil {
		return nil, metadataPath, err
	}
	defer f.Close()

	var metadata ModulesMetadata
	if err := json.NewDecoder(f).Decode(&metadata); err != nil {
		return nil, metadataPath, err
	}

	return &metadata, metadataPath, nil
}
