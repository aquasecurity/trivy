package dpkg

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/pkg/dpkg"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"

	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	handler.RegisterPostHandlerInit(types.DpkgLicensePostHandler, newDpkgLicensePostHandler)
}

const version = 1

type dpkgLicensePostHandler struct{}

func newDpkgLicensePostHandler(artifact.Option) (handler.PostHandler, error) {
	return dpkgLicensePostHandler{}, nil
}

// Handle adds licenses to dpkg files
func (h dpkgLicensePostHandler) Handle(_ context.Context, _ *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	licenses := map[string]string{}
	var customResources []types.CustomResource
	for _, resource := range blob.CustomResources {
		if resource.Type == dpkg.LicenseAdder {
			if r, ok := resource.Data.(string); ok {
				licenses[resource.FilePath] = r
			}
		} else {
			// we don't need to include into Result list of all dpkg licenses
			// remove dpkg licenses from CustomResources
			customResources = append(customResources, resource)
		}
	}

	var infos []types.PackageInfo
	for _, pkgInfo := range blob.PackageInfos {

		for i, pkg := range pkgInfo.Packages {
			license, ok := licenses[pkg.Name]
			if ok {
				pkgInfo.Packages[i].License = license
			}
		}
		infos = append(infos, pkgInfo)
	}

	blob.PackageInfos = infos
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
