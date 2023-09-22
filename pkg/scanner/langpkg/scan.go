package langpkg

import (
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/detector/library"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	PkgTargets = map[ftypes.LangType]string{
		ftypes.PythonPkg: "Python",
		ftypes.CondaPkg:  "Conda",
		ftypes.GemSpec:   "Ruby",
		ftypes.NodePkg:   "Node.js",
		ftypes.Jar:       "Java",
	}
)

type Scanner interface {
	Packages(detail ftypes.ArtifactDetail, options types.ScanOptions) types.Results
	Scan(detail ftypes.ArtifactDetail, options types.ScanOptions) (types.Results, error)
}

type scanner struct{}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Packages(detail ftypes.ArtifactDetail, _ types.ScanOptions) types.Results {
	var results types.Results
	for _, app := range detail.Applications {
		if len(app.Libraries) == 0 {
			continue
		}
		target := app.FilePath
		if t, ok := PkgTargets[app.Type]; ok && target == "" {
			// When the file path is empty, we will overwrite it with the pre-defined value.
			target = t
		}

		results = append(results, types.Result{
			Target:   target,
			Class:    types.ClassLangPkg,
			Type:     app.Type,
			Packages: app.Libraries,
		})
	}
	return results
}

func (s *scanner) Scan(detail ftypes.ArtifactDetail, _ types.ScanOptions) (types.Results, error) {
	apps := detail.Applications
	log.Logger.Infof("Number of language-specific files: %d", len(apps))
	if len(apps) == 0 {
		return nil, nil
	}

	var results types.Results
	printedTypes := map[ftypes.LangType]struct{}{}
	for _, app := range apps {
		if len(app.Libraries) == 0 {
			continue
		}

		// Prevent the same log messages from being displayed many times for the same type.
		if _, ok := printedTypes[app.Type]; !ok {
			log.Logger.Infof("Detecting %s vulnerabilities...", app.Type)
			printedTypes[app.Type] = struct{}{}
		}

		log.Logger.Debugf("Detecting library vulnerabilities, type: %s, path: %s", app.Type, app.FilePath)
		vulns, err := library.Detect(app.Type, app.Libraries)
		if err != nil {
			return nil, xerrors.Errorf("failed vulnerability detection of libraries: %w", err)
		} else if len(vulns) == 0 {
			continue
		}

		target := app.FilePath
		if t, ok := PkgTargets[app.Type]; ok && target == "" {
			// When the file path is empty, we will overwrite it with the pre-defined value.
			target = t
		}

		results = append(results, types.Result{
			Target:          target,
			Vulnerabilities: vulns,
			Class:           types.ClassLangPkg,
			Type:            app.Type,
		})
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results, nil
}
