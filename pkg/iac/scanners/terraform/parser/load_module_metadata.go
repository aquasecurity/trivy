package parser

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"

	"github.com/aquasecurity/trivy/pkg/log"
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

// loadModulesMetadata reads .terraform/modules/modules.json of the project from the module filesystem.
// It returns nil if the file is missing or cannot be read.
func (p *Parser) loadModulesMetadata() *ModulesMetadata {
	metadata, metadataPath, err := loadModuleMetadata(p.moduleFS, p.projectRoot)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			p.logger.Error("Error loading module metadata", log.Err(err))
		}
		return nil
	}

	p.logger.Debug("Loaded module metadata for modules",
		log.FilePath(metadataPath),
		log.Int("count", len(metadata.Modules)),
	)
	return metadata
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
