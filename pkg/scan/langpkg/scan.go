package langpkg

import (
	"context"
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/detector/library"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
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
	Scan(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (types.Results, error)
}

type scanner struct{}

func NewScanner() Scanner {
	return &scanner{}
}

func (s *scanner) Scan(ctx context.Context, target types.ScanTarget, opts types.ScanOptions) (types.Results, error) {
	apps := target.Applications
	log.Info("Number of language-specific files", log.Int("num", len(apps)))
	if len(apps) == 0 {
		return nil, nil
	}

	var results types.Results
	printedTypes := set.New[ftypes.LangType]()
	for _, app := range apps {
		if len(app.Packages) == 0 {
			continue
		}

		ctx = log.WithContextPrefix(ctx, string(app.Type))
		result := types.Result{
			Target: targetName(app.Type, app.FilePath),
			Class:  types.ClassLangPkg,
			Type:   app.Type,
		}

		sort.Sort(app.Packages)
		result.Packages = app.Packages

		if opts.Scanners.Enabled(types.VulnerabilityScanner) {
			var err error
			result.Vulnerabilities, err = s.scanVulnerabilities(ctx, app, printedTypes)
			if err != nil {
				return nil, err
			}
		}

		if len(result.Packages) == 0 && len(result.Vulnerabilities) == 0 {
			continue
		}
		results = append(results, result)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})
	return results, nil
}

func (s *scanner) scanVulnerabilities(ctx context.Context, app ftypes.Application, printedTypes set.Set[ftypes.LangType]) (
	[]types.DetectedVulnerability, error) {

	// Prevent the same log messages from being displayed many times for the same type.
	if !printedTypes.Contains(app.Type) {
		log.InfoContext(ctx, "Detecting vulnerabilities...")
		printedTypes.Append(app.Type)
	}

	log.DebugContext(ctx, "Scanning packages for vulnerabilities", log.FilePath(app.FilePath))
	vulns, err := library.Detect(ctx, app.Type, app.Packages)
	if err != nil {
		return nil, xerrors.Errorf("failed vulnerability detection of libraries: %w", err)
	}
	return vulns, err
}

func targetName(appType ftypes.LangType, filePath string) string {
	if t, ok := PkgTargets[appType]; ok && filePath == "" {
		// When the file path is empty, we will overwrite it with the pre-defined value.
		return t
	}
	return filePath
}
