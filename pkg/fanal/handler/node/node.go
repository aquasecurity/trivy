package node

import (
	"context"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	handler.RegisterPostHandlerInit(types.NodeLicensesPostHandler, newNodeLicensesMergeHandler)
}

const version = 1

// This handler only works in `fs` mode
// It moves licenses from `package.json` to `package-lock.json`
// then removes `package.json` from the result
type nodeLicensesMergeHandler struct{}

func newNodeLicensesMergeHandler(artifact.Option) (handler.PostHandler, error) {
	return nodeLicensesMergeHandler{}, nil
}

// Handle merge licenses from `package.json` to `package-lock.json`
func (h nodeLicensesMergeHandler) Handle(_ context.Context, _ *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	var apps []types.Application
	nodePkgs := map[string][]types.Package{}

	// separating node packages from other applications
	for _, app := range blob.Applications {
		if app.Type == types.NodePkg {
			// take filepath to node_modules folder
			filepath := strings.Split(app.FilePath, "node_modules")
			if len(filepath) != 1 { // skip `package.json` not in node_modules folder
				baseFilePath := filepath[0]
				nodePkgs[baseFilePath] = append(nodePkgs[baseFilePath], app.Libraries...)
			}
		} else {
			apps = append(apps, app) // save other applications
		}
	}

	// merge licenses from node packages to npm
	for i, app := range apps {
		if app.Type == types.Npm {
			filepath := strings.TrimSuffix(app.FilePath, types.NpmPkgLock)
			for j, lib := range app.Libraries {
				// take only packets with the same base path
				// e.g. app/package-lock.json => app/node_modules/foo/package.json
				for _, pkg := range nodePkgs[filepath] {
					if lib.Name == pkg.Name || lib.Version == pkg.Version {
						apps[i].Libraries[j].Licenses = pkg.Licenses
					}
				}
			}

		}
	}

	blob.Applications = apps
	return nil
}

func (h nodeLicensesMergeHandler) Version() int {
	return version
}

func (h nodeLicensesMergeHandler) Type() types.HandlerType {
	return types.NodeLicensesPostHandler
}

func (h nodeLicensesMergeHandler) Priority() int {
	return types.NodeLicensesPostHandlerPriority
}
