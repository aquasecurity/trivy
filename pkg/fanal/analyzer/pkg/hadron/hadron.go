package hadron

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(newHadronAnalyzer())
}

const analyzerVersion = 1

// componentsFile is the path (relative to the artifact root) of the Hadron
// component inventory. Hadron has no traditional package manager and records
// installed component versions in this flat JSON file.
const componentsFile = "usr/lib/hadron/components.json"

type hadronAnalyzer struct{}

func newHadronAnalyzer() *hadronAnalyzer {
	return &hadronAnalyzer{}
}

// components is the on-disk format of components.json: a flat map of
// component name to version, e.g. {"openssl": "3.6.3", "curl": "8.21.0"}.
type components map[string]string

func (a hadronAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	pkgs, err := a.parseComponents(input.Content)
	if err != nil {
		return nil, err
	}

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: pkgs,
			},
		},
	}, nil
}

func (a hadronAnalyzer) parseComponents(r io.Reader) (types.Packages, error) {
	var comps components
	if err := json.NewDecoder(r).Decode(&comps); err != nil {
		return nil, fmt.Errorf("failed to decode Hadron components.json: %w", err)
	}

	var pkgs types.Packages
	for name, ver := range comps {
		// Skip incomplete entries defensively.
		if name == "" || ver == "" {
			continue
		}
		pkgs = append(pkgs, types.Package{
			ID:      fmt.Sprintf("%s@%s", name, ver),
			Name:    name,
			Version: ver,
		})
	}

	// components.json is an unordered JSON object; sort for deterministic output.
	sort.Sort(pkgs)

	return pkgs, nil
}

func (a hadronAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filePath == componentsFile
}

func (a hadronAnalyzer) Type() analyzer.Type {
	return analyzer.TypeHadron
}

func (a hadronAnalyzer) Version() int {
	return analyzerVersion
}

// StaticPaths returns a list of static file paths to analyze
func (a hadronAnalyzer) StaticPaths() []string {
	return []string{componentsFile}
}
