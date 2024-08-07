package snapshot

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/liamg/memoryfs"
	"github.com/zclconf/go-cty/cty"

	iox "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	configSnapshotPrefix       = "tfconfig/"
	configSnapshotManifestFile = configSnapshotPrefix + "modules.json"
	configSnapshotModulePrefix = configSnapshotPrefix + "m-"

	tfplanFilename = "tfplan"
)

type (
	configSnapshotModuleRecord struct {
		Key        string `json:"Key"`
		SourceAddr string `json:"Source,omitempty"`
		Dir        string `json:"Dir"`
	}

	configSnapshotModuleManifest []configSnapshotModuleRecord
)

var errNoTerraformPlan = errors.New("no terraform plan file")

func IsPlanSnapshot(r io.Reader) bool {
	zr, err := readSnapshot(r)
	if err != nil {
		return false
	}
	return containsTfplanFile(zr)
}

func readSnapshot(r io.Reader) (*zip.Reader, error) {
	if r == nil {
		return nil, errors.New("reader is nil")
	}

	rsa, size, err := iox.NewReadSeekerAtWithSize(r)
	if err != nil {
		return nil, err
	}

	zr, err := zip.NewReader(rsa, size)
	if err != nil {
		return nil, err
	}

	return zr, nil
}

func parseSnapshot(r io.Reader) (*snapshot, error) {
	zr, err := readSnapshot(r)
	if err != nil {
		return nil, err
	}

	if !containsTfplanFile(zr) {
		return nil, errNoTerraformPlan
	}

	snap := &snapshot{
		modules:        make(map[string]*snapshotModule),
		inputVariables: make(map[string]cty.Value),
	}

	var moduleManifest configSnapshotModuleManifest

	for _, file := range zr.File {
		switch {
		case file.Name == configSnapshotManifestFile:
			var err error
			moduleManifest, err = readModuleManifest(file)
			if err != nil {
				return nil, err
			}
		case strings.HasPrefix(file.Name, configSnapshotModulePrefix):
			if err := snap.addFile(file); err != nil {
				return nil, err
			}
		case file.Name == tfplanFilename:
			r, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open plan: %w", err)
			}

			plan, err := readTfPlan(r)
			if err != nil {
				_ = r.Close()
				return nil, fmt.Errorf("failed to read tfplan: %w", err)
			}
			_ = r.Close()

			snap.inputVariables, err = plan.inputVariables()
			if err != nil {
				return nil, err
			}
		}
	}

	for _, record := range moduleManifest {
		// skip non-local modules
		if record.Dir != "." && !strings.HasPrefix(record.SourceAddr, ".") {
			delete(snap.modules, record.Key)
			continue
		}
		modSnap := snap.getOrCreateModuleSnapshot(record.Key)
		modSnap.dir = record.Dir
	}

	return snap, nil
}

func containsTfplanFile(zr *zip.Reader) bool {
	return slices.ContainsFunc(zr.File, func(f *zip.File) bool {
		return f.Name == tfplanFilename
	})
}

func readModuleManifest(f *zip.File) (configSnapshotModuleManifest, error) {
	r, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open module manifest: %s", r)
	}
	defer r.Close()

	var manifest configSnapshotModuleManifest
	if err := json.NewDecoder(r).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to read module manifest: %s", f.Name)
	}
	return manifest, nil
}

type (
	snapshotModule struct {
		// dir is the path, relative to the root directory given when the
		// snapshot was created, where the module appears in the snapshot's
		// virtual filesystem.
		dir string

		// files is a map from each configuration file filename for the
		// module to a raw byte representation of the source file contents.
		files map[string][]byte
	}

	snapshot struct {
		modules        map[string]*snapshotModule
		inputVariables map[string]cty.Value
	}
)

func (s *snapshot) addFile(file *zip.File) error {
	relName := file.Name[len(configSnapshotModulePrefix):]
	moduleKey, fileName := path.Split(relName)
	if moduleKey == "" {
		return nil
	}
	moduleKey = moduleKey[:len(moduleKey)-1]

	r, err := file.Open()
	if err != nil {
		return fmt.Errorf("failed to open snapshot of %s from module %q: %s", fileName, moduleKey, err)
	}
	defer r.Close()

	fileSrc, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("failed to read snapshot of %s from module %q: %s", fileName, moduleKey, err)
	}

	modSnap := s.getOrCreateModuleSnapshot(moduleKey)
	modSnap.files[fileName] = fileSrc
	return nil
}

func (s *snapshot) getOrCreateModuleSnapshot(key string) *snapshotModule {
	modSnap, exists := s.modules[key]
	if !exists {
		modSnap = &snapshotModule{
			files: make(map[string][]byte),
		}
		s.modules[key] = modSnap
	}
	return modSnap
}

func (s *snapshot) toFS() (fs.FS, error) {
	fsys := memoryfs.New()

	for _, module := range s.modules {
		if err := fsys.MkdirAll(module.dir, fs.ModePerm); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		for filename, file := range module.files {
			filePath := filename
			if module.dir != "" {
				filePath = path.Join(module.dir, filename)
			}
			if err := fsys.WriteFile(filePath, file, fs.ModePerm); err != nil {
				return nil, fmt.Errorf("failed to add file: %w", err)
			}
		}
	}
	return fsys, nil
}
