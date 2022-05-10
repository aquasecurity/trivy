package redhatoval

import (
	"encoding/json"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

type rpmInfoTest struct {
	Name           string
	SignatureKeyID signatureKeyID
	FixedVersion   string
	Arch           string
}

func unmarshalJSONFile(v interface{}, fileName string) error {
	f, err := os.Open(fileName)
	if err != nil {
		return xerrors.Errorf("unable to open a file (%s): %w", fileName, err)
	}
	defer f.Close()

	if err = json.NewDecoder(f).Decode(v); err != nil {
		return xerrors.Errorf("failed to decode Red Hat OVAL JSON: %w", err)
	}
	return nil
}

func parseObjects(dir string) (map[string]string, error) {
	var objects ovalObjects
	if err := unmarshalJSONFile(&objects, filepath.Join(dir, "objects", "objects.json")); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal objects: %w", err)
	}
	objs := map[string]string{}
	for _, obj := range objects.RpminfoObjects {
		objs[obj.ID] = obj.Name
	}
	return objs, nil
}

func parseStates(dir string) (map[string]rpminfoState, error) {
	var ss ovalStates
	if err := unmarshalJSONFile(&ss, filepath.Join(dir, "states", "states.json")); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal states: %w", err)
	}

	states := map[string]rpminfoState{}
	for _, state := range ss.RpminfoState {
		states[state.ID] = state
	}
	return states, nil
}

func parseTests(dir string) (map[string]rpmInfoTest, error) {
	objects, err := parseObjects(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse objects: %w", err)
	}

	states, err := parseStates(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse states: %w", err)
	}

	var tt ovalTests
	if err := unmarshalJSONFile(&tt, filepath.Join(dir, "tests", "tests.json")); err != nil {
		return nil, xerrors.Errorf("failed to unmarshal states: %w", err)
	}

	tests := map[string]rpmInfoTest{}
	for _, test := range tt.RpminfoTests {
		// test.Check should be "at least one"
		if test.Check != "at least one" {
			continue
		}

		t, err := followTestRefs(test, objects, states)
		if err != nil {
			return nil, xerrors.Errorf("unable to follow test refs: %w", err)
		}
		tests[test.ID] = t
	}
	return tests, nil
}

func followTestRefs(test rpminfoTest, objects map[string]string, states map[string]rpminfoState) (rpmInfoTest, error) {
	var t rpmInfoTest

	// Follow object ref
	if test.Object.ObjectRef == "" {
		return t, nil
	}

	pkgName, ok := objects[test.Object.ObjectRef]
	if !ok {
		return t, xerrors.Errorf("invalid tests data, can't find object ref: %s, test ref: %s",
			test.Object.ObjectRef, test.ID)
	}
	t.Name = pkgName

	// Follow state ref
	if test.State.StateRef == "" {
		return t, nil
	}

	state, ok := states[test.State.StateRef]
	if !ok {
		return t, xerrors.Errorf("invalid tests data, can't find ovalstate ref %s, test ref: %s",
			test.State.StateRef, test.ID)
	}

	t.SignatureKeyID = state.SignatureKeyID

	if state.Arch.Datatype == "string" && (state.Arch.Operation == "pattern match" || state.Arch.Operation == "equals") {
		t.Arch = state.Arch.Text
	}

	if state.Evr.Datatype == "evr_string" && state.Evr.Operation == "less than" {
		t.FixedVersion = state.Evr.Text
	}

	return t, nil
}
