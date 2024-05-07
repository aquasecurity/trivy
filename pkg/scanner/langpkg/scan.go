package langpkg

import (
	"context"
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/detector/library"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	PkgTargets = map[ftypes.LangType]string{
		ftypes.PythonPkg:   "Python",
		ftypes.CondaPkg:    "Conda",
		ftypes.GemSpec:     "Ruby",
		ftypes.NodePkg:     "Node.js",
		ftypes.Jar:         "Java",
		ftypes.K8sUpstream: "Kubernetes",
	}
)

type Scanner interface {
	Packages(target types.ScanTarget, options types.ScanOptions) types.Results
	Scan(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (types.Results, error)
}

type scanner struct{}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Packages(target types.ScanTarget, _ types.ScanOptions) types.Results {
	var results types.Results
	for _, app := range target.Applications {
		if len(app.Packages) == 0 {
			continue
		}

		results = append(results, types.Result{
			Target:   targetName(app.Type, app.FilePath),
			Class:    types.ClassLangPkg,
			Type:     app.Type,
			Packages: app.Packages,
		})
	}
	return results
}

func (s *scanner) Scan(ctx context.Context, target types.ScanTarget, _ types.ScanOptions) (types.Results, error) {
	apps := target.Applications
	log.Info("Number of language-specific files", log.Int("num", len(apps)))
	if len(apps) == 0 {
		return nil, nil
	}

	var results types.Results
	printedTypes := make(map[ftypes.LangType]struct{})
	for _, app := range apps {
		if len(app.Packages) == 0 {
			continue
		}

		ctx = log.WithContextPrefix(ctx, string(app.Type))

		// Prevent the same log messages from being displayed many times for the same type.
		if _, ok := printedTypes[app.Type]; !ok {
			log.InfoContext(ctx, "Detecting vulnerabilities...")
			printedTypes[app.Type] = struct{}{}
		}

		log.DebugContext(ctx, "Scanning packages from the file", log.String("file_path", app.FilePath))
		vulns, err := library.Detect(ctx, app.Type, app.Packages)
		if err != nil {
			return nil, xerrors.Errorf("failed vulnerability detection of packages: %w", err)
		} else if len(vulns) == 0 {
			continue
		}

		results = append(results, types.Result{
			Target:          targetName(app.Type, app.FilePath),
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

func targetName(appType ftypes.LangType, filePath string) string {
	if t, ok := PkgTargets[appType]; ok && filePath == "" {
		// When the file path is empty, we will overwrite it with the pre-defined value.
		return t
	}
	return filePath
}
