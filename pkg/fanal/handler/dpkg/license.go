package dpkg

import (
	"context"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"

	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	types "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	handler.RegisterPostHandlerInit(types.DpkgLicensePostHandler, newDpkgLicensePostHandler)
}

const version = 1

type dpkgLicensePostHandler struct{}

func newDpkgLicensePostHandler(artifact.Option) (handler.PostHandler, error) {
	return dpkgLicensePostHandler{}, nil
}

// Handle adds licenses to dpkg packages
func (h dpkgLicensePostHandler) Handle(_ context.Context, _ *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	licenses := map[string]string{}
	var customResources []types.CustomResource
	for _, resource := range blob.CustomResources {
		if resource.Type == string(types.DpkgLicensePostHandler) {
			if r, ok := resource.Data.(string); ok {
				// e.g. "usr/share/doc/zlib1g/copyright" => "zlib1g"
				pkgName := strings.Split(resource.FilePath, "/")[3]
				licenses[pkgName] = r
			}
		} else {
			// we don't need to include dpkg licenses in the Result list
			// remove dpkg licenses from CustomResources
			customResources = append(customResources, resource)
		}
	}

	for i, pkgInfo := range blob.PackageInfos {
		for j, pkg := range pkgInfo.Packages {
			if license, ok := licenses[pkg.Name]; ok {
				blob.PackageInfos[i].Packages[j].License = license
			}
		}
	}

	blob.CustomResources = customResources
	return nil
}

func (h dpkgLicensePostHandler) Version() int {
	return version
}

func (h dpkgLicensePostHandler) Type() types.HandlerType {
	return types.DpkgLicensePostHandler
}

func (h dpkgLicensePostHandler) Priority() int {
	return types.DpkgLicensePostHandlerPriority
}
