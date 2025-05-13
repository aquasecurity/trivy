package nodejs

import (
	"context"
	"slices"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	handler.RegisterPostHandlerInit(types.SystemFileFilteringPostHandler, newSystemFileFilteringPostHandler)
}

const version = 1

var defaultSystemFiles = []string{
	// TODO: Google Distroless removes /var/lib/dpkg/info/*.list, so we cannot know which files are installed by dpkg.
	//       We have to hardcode these files at the moment, but should look for the better way.
	"/usr/lib/python2.7/argparse.egg-info",
	"/usr/lib/python2.7/lib-dynload/Python-2.7.egg-info",
	"/usr/lib/python2.7/wsgiref.egg-info",
}

type systemFileFilteringPostHandler struct{}

func newSystemFileFilteringPostHandler(artifact.Option) (handler.PostHandler, error) {
	return systemFileFilteringPostHandler{}, nil
}

// Handle removes files installed by OS package manager such as yum.
func (h systemFileFilteringPostHandler) Handle(_ context.Context, result *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	var systemFiles []string
	for _, file := range append(result.SystemInstalledFiles, defaultSystemFiles...) {
		// Trim leading slashes to be the same format as the path in container images.
		systemFile := strings.TrimPrefix(file, "/")
		// We should check the root filepath ("/") and ignore it.
		// Otherwise, packages with an empty filePath will be removed.
		if systemFile != "" {
			systemFiles = append(systemFiles, systemFile)
		}
	}

	var apps []types.Application
	for _, app := range blob.Applications {
		// If the lang-specific package was installed by OS package manager, it should not be taken.
		// Otherwise, the package version will be wrong, then it will lead to false positive.
		if slices.Contains(systemFiles, app.FilePath) {
			continue
		}

		var pkgs []types.Package
		for _, lib := range app.Packages {
			// If the lang-specific package was installed by OS package manager, it should not be taken.
			// Otherwise, the package version will be wrong, then it will lead to false positive.
			if slices.Contains(systemFiles, lib.FilePath) {
				continue
			}
			pkgs = append(pkgs, lib)
		}

		// Overwrite Packages
		app.Packages = pkgs
		apps = append(apps, app)
	}

	// Iterate and delete unnecessary customResource
	i := 0
	for _, res := range blob.CustomResources {
		if slices.Contains(systemFiles, res.FilePath) {
			continue
		}
		blob.CustomResources[i] = res
		i++
	}
	blob.CustomResources = blob.CustomResources[:i]

	// Overwrite Applications
	blob.Applications = apps

	return nil
}

func (h systemFileFilteringPostHandler) Version() int {
	return version
}

func (h systemFileFilteringPostHandler) Type() types.HandlerType {
	return types.SystemFileFilteringPostHandler
}

func (h systemFileFilteringPostHandler) Priority() int {
	return types.SystemFileFilteringPostHandlerPriority
}
