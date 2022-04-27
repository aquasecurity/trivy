package oval

import (
	"encoding/json"
	"io"
	"path/filepath"

	"github.com/aquasecurity/trivy-db/pkg/utils"

	"golang.org/x/xerrors"
)

func ParseDefinitions(dir string) ([]Definition, error) {
	dir = filepath.Join(dir, "definitions")
	if exists, _ := utils.Exists(dir); !exists {
		return nil, xerrors.Errorf("no definitions dir")
	}

	var defs []Definition

	err := utils.FileWalk(dir, func(r io.Reader, path string) error {
		var def Definition
		if err := json.NewDecoder(r).Decode(&def); err != nil {
			return xerrors.Errorf("failed to decode %s: %w", path, err)
		}
		defs = append(defs, def)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("CBL-Mariner OVAL walk error: %w", err)
	}

	return defs, nil
}

func ParseTests(dir string) (Tests, error) {
	var tests Tests
	if err := utils.UnmarshalJSONFile(&tests, filepath.Join(dir, "tests", "tests.json")); err != nil {
		return tests, xerrors.Errorf("failed to unmarshal tests: %w", err)
	}
	return tests, nil
}

func ParseObjects(dir string) (map[string]string, error) {
	var objects Objects
	if err := utils.UnmarshalJSONFile(&objects, filepath.Join(dir, "objects", "objects.json")); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal objects: %w", err)
	}
	objs := map[string]string{}
	for _, obj := range objects.RpminfoObjects {
		objs[obj.ID] = obj.Name
	}
	return objs, nil
}

func ParseStates(dir string) (map[string]RpmInfoState, error) {
	var ss States
	if err := utils.UnmarshalJSONFile(&ss, filepath.Join(dir, "states", "states.json")); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal states: %w", err)
	}

	states := map[string]RpmInfoState{}
	for _, state := range ss.RpminfoState {
		states[state.ID] = state
	}
	return states, nil
}
