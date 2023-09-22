package applier

import (
	"fmt"
	"strings"
	"time"

	"github.com/knqyf263/nested"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type Config struct {
	ContainerConfig containerConfig `json:"container_config"`
	History         []History
}

type containerConfig struct {
	Env []string
}

type History struct {
	Created   time.Time
	CreatedBy string `json:"created_by"`
}

func containsPackage(e types.Package, s []types.Package) bool {
	for _, a := range s {
		if a.Name == e.Name && a.Version == e.Version && a.Release == e.Release {
			return true
		}
	}
	return false
}

func lookupOriginLayerForPkg(pkg types.Package, layers []types.BlobInfo) (string, string, *types.BuildInfo) {
	for i, layer := range layers {
		for _, info := range layer.PackageInfos {
			if containsPackage(pkg, info.Packages) {
				return layer.Digest, layer.DiffID, lookupBuildInfo(i, layers)
			}
		}
	}
	return "", "", nil
}

// lookupBuildInfo looks up Red Hat content sets from all layers
func lookupBuildInfo(index int, layers []types.BlobInfo) *types.BuildInfo {
	if layers[index].BuildInfo != nil {
		return layers[index].BuildInfo
	}

	// Base layer (layers[0]) is missing content sets
	//   - it needs to be shared from layers[1]
	if index == 0 {
		if len(layers) > 1 {
			return layers[1].BuildInfo
		}
		return nil
	}

	// Customer's layers build on top of Red Hat image are also missing content sets
	//   - it needs to be shared from the last Red Hat's layers which contains content sets
	for i := index - 1; i >= 1; i-- {
		if layers[i].BuildInfo != nil {
			return layers[i].BuildInfo
		}
	}
	return nil
}

func lookupOriginLayerForLib(filePath string, lib types.Package, layers []types.BlobInfo) (string, string) {
	for _, layer := range layers {
		for _, layerApp := range layer.Applications {
			if filePath != layerApp.FilePath {
				continue
			}
			if containsPackage(lib, layerApp.Libraries) {
				return layer.Digest, layer.DiffID
			}
		}
	}
	return "", ""
}

// ApplyLayers returns the merged layer
// nolint: gocyclo
func ApplyLayers(layers []types.BlobInfo) types.ArtifactDetail {
	sep := "/"
	nestedMap := nested.Nested{}
	secretsMap := map[string]types.Secret{}
	var mergedLayer types.ArtifactDetail

	for _, layer := range layers {
		for _, opqDir := range layer.OpaqueDirs {
			opqDir = strings.TrimSuffix(opqDir, sep)  // this is necessary so that an empty element is not contribute into the array of the DeleteByString function
			_ = nestedMap.DeleteByString(opqDir, sep) // nolint
		}
		for _, whFile := range layer.WhiteoutFiles {
			_ = nestedMap.DeleteByString(whFile, sep) // nolint
		}

		mergedLayer.OS.Merge(layer.OS)

		if layer.Repository != nil {
			mergedLayer.Repository = layer.Repository
		}

		// Apply OS packages
		for _, pkgInfo := range layer.PackageInfos {
			key := fmt.Sprintf("%s/type:ospkg", pkgInfo.FilePath)
			nestedMap.SetByString(key, sep, pkgInfo)
		}

		// Apply language-specific packages
		for _, app := range layer.Applications {
			key := fmt.Sprintf("%s/type:%s", app.FilePath, app.Type)
			nestedMap.SetByString(key, sep, app)
		}

		// Apply misconfigurations
		for _, config := range layer.Misconfigurations {
			config.Layer = types.Layer{
				Digest: layer.Digest,
				DiffID: layer.DiffID,
			}
			key := fmt.Sprintf("%s/type:config", config.FilePath)
			nestedMap.SetByString(key, sep, config)
		}

		// Apply secrets
		for _, secret := range layer.Secrets {
			l := types.Layer{
				Digest:    layer.Digest,
				DiffID:    layer.DiffID,
				CreatedBy: layer.CreatedBy,
			}
			secretsMap = mergeSecrets(secretsMap, secret, l)
		}

		// Apply license files
		for _, license := range layer.Licenses {
			license.Layer = types.Layer{
				Digest: layer.Digest,
				DiffID: layer.DiffID,
			}
			key := fmt.Sprintf("%s/type:license,%s", license.FilePath, license.Type)
			nestedMap.SetByString(key, sep, license)
		}

		// Apply custom resources
		for _, customResource := range layer.CustomResources {
			key := fmt.Sprintf("%s/custom:%s", customResource.FilePath, customResource.Type)
			customResource.Layer = types.Layer{
				Digest: layer.Digest,
				DiffID: layer.DiffID,
			}
			nestedMap.SetByString(key, sep, customResource)
		}
	}

	// nolint
	_ = nestedMap.Walk(func(keys []string, value interface{}) error {
		switch v := value.(type) {
		case types.PackageInfo:
			mergedLayer.Packages = append(mergedLayer.Packages, v.Packages...)
		case types.Application:
			mergedLayer.Applications = append(mergedLayer.Applications, v)
		case types.Misconfiguration:
			mergedLayer.Misconfigurations = append(mergedLayer.Misconfigurations, v)
		case types.LicenseFile:
			mergedLayer.Licenses = append(mergedLayer.Licenses, v)
		case types.CustomResource:
			mergedLayer.CustomResources = append(mergedLayer.CustomResources, v)
		}
		return nil
	})

	for _, s := range secretsMap {
		mergedLayer.Secrets = append(mergedLayer.Secrets, s)
	}

	// Extract dpkg licenses
	// The license information is not stored in the dpkg database and in a separate file,
	// so we have to merge the license information into the package.
	dpkgLicenses := map[string][]string{}
	mergedLayer.Licenses = lo.Reject(mergedLayer.Licenses, func(license types.LicenseFile, _ int) bool {
		if license.Type != types.LicenseTypeDpkg {
			return false
		}
		// e.g.
		//	"adduser" => {"GPL-2"}
		//  "openssl" => {"MIT", "BSD"}
		dpkgLicenses[license.PkgName] = lo.Map(license.Findings, func(finding types.LicenseFinding, _ int) string {
			return finding.Name
		})
		// Remove this license in the merged result as it is merged into the package information.
		return true
	})
	if len(mergedLayer.Licenses) == 0 {
		mergedLayer.Licenses = nil
	}

	for i, pkg := range mergedLayer.Packages {
		originLayerDigest, originLayerDiffID, buildInfo := lookupOriginLayerForPkg(pkg, layers)
		mergedLayer.Packages[i].Layer = types.Layer{
			Digest: originLayerDigest,
			DiffID: originLayerDiffID,
		}
		mergedLayer.Packages[i].BuildInfo = buildInfo

		// Only debian packages
		if licenses, ok := dpkgLicenses[pkg.Name]; ok {
			mergedLayer.Packages[i].Licenses = licenses
		}
	}

	for _, app := range mergedLayer.Applications {
		for i, lib := range app.Libraries {
			originLayerDigest, originLayerDiffID := lookupOriginLayerForLib(app.FilePath, lib, layers)
			app.Libraries[i].Layer = types.Layer{
				Digest: originLayerDigest,
				DiffID: originLayerDiffID,
			}
		}
	}

	// Aggregate python/ruby/node.js packages and JAR files
	aggregate(&mergedLayer)

	return mergedLayer
}

// aggregate merges all packages installed by pip/gem/npm/jar/conda into each application
func aggregate(detail *types.ArtifactDetail) {
	var apps []types.Application

	aggregatedApps := map[types.LangType]*types.Application{
		types.PythonPkg: {Type: types.PythonPkg},
		types.CondaPkg:  {Type: types.CondaPkg},
		types.GemSpec:   {Type: types.GemSpec},
		types.NodePkg:   {Type: types.NodePkg},
		types.Jar:       {Type: types.Jar},
	}

	for _, app := range detail.Applications {
		a, ok := aggregatedApps[app.Type]
		if !ok {
			apps = append(apps, app)
			continue
		}
		a.Libraries = append(a.Libraries, app.Libraries...)
	}

	for _, app := range aggregatedApps {
		if len(app.Libraries) > 0 {
			apps = append(apps, *app)
		}
	}

	// Overwrite Applications
	detail.Applications = apps
}

// We must save secrets from all layers even though they are removed in the uppler layer.
// If the secret was changed at the top level, we need to overwrite it.
func mergeSecrets(secretsMap map[string]types.Secret, newSecret types.Secret, layer types.Layer) map[string]types.Secret {
	for i := range newSecret.Findings { // add layer to the Findings from the new secret
		newSecret.Findings[i].Layer = layer
	}

	secret, ok := secretsMap[newSecret.FilePath]
	if !ok {
		// Add the new finding if its file doesn't exist before
		secretsMap[newSecret.FilePath] = newSecret
	} else {
		// If the new finding has the same `RuleID` as the finding in the previous layers - use the new finding
		for _, previousFinding := range secret.Findings { // secrets from previous layers
			if !secretFindingsContains(newSecret.Findings, previousFinding) {
				newSecret.Findings = append(newSecret.Findings, previousFinding)
			}
		}
		secretsMap[newSecret.FilePath] = newSecret
	}
	return secretsMap
}

func secretFindingsContains(findings []types.SecretFinding, finding types.SecretFinding) bool {
	for _, f := range findings {
		if f.RuleID == finding.RuleID {
			return true
		}
	}
	return false
}
