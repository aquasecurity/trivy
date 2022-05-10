package mariner

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/mariner/oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

var (
	cblDir         = filepath.Join("mariner")
	platformFormat = "CBL-Mariner %s"

	source = types.DataSource{
		ID:   vulnerability.CBLMariner,
		Name: "CBL-Mariner Vulnerability Data",
		URL:  "https://github.com/microsoft/CBL-MarinerVulnerabilityData",
	}

	ErrNotSupported = xerrors.New("format not supported")
)

type resolvedTest struct {
	Name     string
	Version  string
	Operator operator
}

type VulnSrc struct {
	dbc db.Operation
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc: db.Config{},
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return source.ID
}

func (vs VulnSrc) Update(dir string) error {
	rootDir := filepath.Join(dir, "vuln-list", cblDir)
	versions, err := os.ReadDir(rootDir)
	if err != nil {
		return xerrors.Errorf("unable to list directory entries (%s): %w", rootDir, err)
	}

	for _, ver := range versions {
		versionDir := filepath.Join(rootDir, ver.Name())
		entries, err := parseOVAL(filepath.Join(versionDir))
		if err != nil {
			return xerrors.Errorf("failed to parse CBL-Mariner OVAL: %w ", err)
		}

		if err = vs.save(ver.Name(), entries); err != nil {
			return xerrors.Errorf("error in CBL-Mariner save: %w", err)
		}
	}

	return nil
}

func parseOVAL(dir string) ([]Entry, error) {
	log.Printf("    Parsing %s", dir)

	// Parse and resolve tests
	tests, err := resolveTests(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to resolve tests: %w", err)
	}

	defs, err := oval.ParseDefinitions(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse definitions: %w", err)
	}

	return resolveDefinitions(defs, tests), nil
}

func resolveDefinitions(defs []oval.Definition, tests map[string]resolvedTest) []Entry {
	var entries []Entry

	for _, def := range defs {
		test, ok := tests[def.Criteria.Criterion.TestRef]
		if !ok {
			continue
		}
		entry := Entry{
			PkgName:  test.Name,
			Version:  test.Version,
			Operator: test.Operator,
			Metadata: def.Metadata,
		}

		entries = append(entries, entry)
	}
	return entries
}

const (
	lte operator = "less than or equal"
	lt  operator = "less than"
)

func resolveTests(dir string) (map[string]resolvedTest, error) {
	objects, err := oval.ParseObjects(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse objects: %w", err)
	}

	states, err := oval.ParseStates(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse states: %w", err)
	}

	tt, err := oval.ParseTests(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse tests: %w", err)
	}

	tests := map[string]resolvedTest{}
	for _, test := range tt.RpminfoTests {
		// test directive has should be "at least one"
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

func followTestRefs(test oval.RpmInfoTest, objects map[string]string, states map[string]oval.RpmInfoState) (resolvedTest, error) {
	// Follow object ref
	if test.Object.ObjectRef == "" {
		return resolvedTest{}, xerrors.New("invalid test, no object ref")
	}

	pkgName, ok := objects[test.Object.ObjectRef]
	if !ok {
		return resolvedTest{}, xerrors.Errorf("invalid test data, can't find object ref: %s, test ref: %s",
			test.Object.ObjectRef, test.ID)
	}

	// Follow state ref
	if test.State.StateRef == "" {
		return resolvedTest{}, xerrors.New("invalid test, no state ref")
	}

	state, ok := states[test.State.StateRef]
	if !ok {
		return resolvedTest{}, xerrors.Errorf("invalid tests data, can't find ovalstate ref %s, test ref: %s",
			test.State.StateRef, test.ID)
	}

	if state.Evr.Datatype != "evr_string" {
		return resolvedTest{}, xerrors.Errorf("state data type (%s): %w", state.Evr.Datatype, ErrNotSupported)
	}

	if state.Evr.Operation != string(lte) && state.Evr.Operation != string(lt) {
		return resolvedTest{}, xerrors.Errorf("state operation (%s): %w", state.Evr.Operation, ErrNotSupported)
	}

	return resolvedTest{
		Name:     pkgName,
		Version:  state.Evr.Text,
		Operator: operator(state.Evr.Operation),
	}, nil
}

func (vs VulnSrc) save(majorVer string, entries []Entry) error {
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		platformName := fmt.Sprintf(platformFormat, majorVer)
		if err := vs.dbc.PutDataSource(tx, platformName, source); err != nil {
			return xerrors.Errorf("failed to put data source: %w", err)
		}

		if err := vs.commit(tx, platformName, entries); err != nil {
			return xerrors.Errorf("CBL-Mariner %s commit error: %w", majorVer, err)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in db batch update: %w", err)
	}
	return nil
}

func (vs VulnSrc) commit(tx *bolt.Tx, platformName string, entries []Entry) error {
	for _, entry := range entries {
		cveID := entry.Metadata.Reference.RefID
		advisory := types.Advisory{}
		if entry.Metadata.Patchable {
			advisory.FixedVersion = entry.Version
		}

		if err := vs.dbc.PutAdvisoryDetail(tx, cveID, entry.PkgName, []string{platformName}, advisory); err != nil {
			return xerrors.Errorf("failed to save CBL-Mariner advisory detail: %w", err)
		}

		severity, _ := types.NewSeverity(strings.ToUpper(entry.Metadata.Severity))
		vuln := types.VulnerabilityDetail{
			Severity:    severity,
			Title:       entry.Metadata.Title,
			Description: entry.Metadata.Description,
			References:  []string{entry.Metadata.Reference.RefURL},
		}
		if err := vs.dbc.PutVulnerabilityDetail(tx, cveID, source.ID, vuln); err != nil {
			return xerrors.Errorf("failed to save CBL-Mariner vulnerability detail: %w", err)
		}

		if err := vs.dbc.PutVulnerabilityID(tx, cveID); err != nil {
			return xerrors.Errorf("failed to save the vulnerability ID: %w", err)
		}
	}
	return nil
}

func (vs VulnSrc) Get(release, pkgName string) ([]types.Advisory, error) {
	bucket := fmt.Sprintf(platformFormat, release)
	advisories, err := vs.dbc.GetAdvisories(bucket, pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get CBL-Marina advisories: %w", err)
	}
	return advisories, nil
}
