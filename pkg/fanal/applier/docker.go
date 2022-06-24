package applier

import (
	"fmt"
	"strings"
	"time"

	"github.com/knqyf263/nested"

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

func ApplyLayers(layers []types.BlobInfo) types.ArtifactDetail {
	sep := "/"
	nestedMap := nested.Nested{}
	var mergedLayer types.ArtifactDetail

	for _, layer := range layers {
		for _, opqDir := range layer.OpaqueDirs {
			opqDir = strings.TrimSuffix(opqDir, sep)  //this is necessary so that an empty element is not contribute into the array of the DeleteByString function
			_ = nestedMap.DeleteByString(opqDir, sep) // nolint
		}
		for _, whFile := range layer.WhiteoutFiles {
			_ = nestedMap.DeleteByString(whFile, sep) // nolint
		}

		if layer.OS != nil {
			mergedLayer.OS = layer.OS
		}

		if layer.Repository != nil {
			mergedLayer.Repository = layer.Repository
		}

		for _, pkgInfo := range layer.PackageInfos {
			key := fmt.Sprintf("%s/type:ospkg", pkgInfo.FilePath)
			//
			pkgInfo = mergeLicense(nestedMap, strings.Split(key, sep), pkgInfo)
			nestedMap.SetByString(key, sep, pkgInfo)
		}
		for _, app := range layer.Applications {
			key := fmt.Sprintf("%s/type:%s", app.FilePath, app.Type)
			nestedMap.SetByString(key, sep, app)
		}
		for _, config := range layer.Misconfigurations {
			config.Layer = types.Layer{
				Digest: layer.Digest,
				DiffID: layer.DiffID,
			}
			key := fmt.Sprintf("%s/type:config", config.FilePath)
			nestedMap.SetByString(key, sep, config)
		}
		for _, secret := range layer.Secrets {
			secret.Layer = types.Layer{
				Digest: layer.Digest,
				DiffID: layer.DiffID,
			}
			key := fmt.Sprintf("%s/type:secret", secret.FilePath)
			nestedMap.SetByString(key, sep, secret)
		}
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
		case types.Secret:
			mergedLayer.Secrets = append(mergedLayer.Secrets, v)
		case types.CustomResource:
			mergedLayer.CustomResources = append(mergedLayer.CustomResources, v)
		}
		return nil
	})

	for i, pkg := range mergedLayer.Packages {
		originLayerDigest, originLayerDiffID, buildInfo := lookupOriginLayerForPkg(pkg, layers)
		mergedLayer.Packages[i].Layer = types.Layer{
			Digest: originLayerDigest,
			DiffID: originLayerDiffID,
		}
		mergedLayer.Packages[i].BuildInfo = buildInfo
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

	// Aggregate python/ruby/node.js packages
	aggregate(&mergedLayer)

	return mergedLayer
}

// aggregate merges all packages installed by pip/gem/npm/jar into each application
func aggregate(detail *types.ArtifactDetail) {
	var apps []types.Application

	aggregatedApps := map[string]*types.Application{
		types.PythonPkg: {Type: types.PythonPkg},
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

// dpkg packageInfo and licenses are in separate files.
// if update only packageInfo in new layer, then this layer will not have licenses
// in this case we overwrite licenses with empty value
// we need to check previous layer if License field is empty
func mergeLicense(nestedMap nested.Nested, key []string, new types.PackageInfo) types.PackageInfo {
	n, err := nestedMap.Get(key)
	if err != nil && err == nested.ErrNoSuchKey {
		return new
	}
	if old, ok := n.(types.PackageInfo); ok {
		for i, newPkg := range new.Packages {
			if newPkg.License == "" {
				for _, oldPkg := range old.Packages {
					if newPkg.Name == oldPkg.Name && newPkg.SrcName == oldPkg.SrcName {
						new.Packages[i].License = oldPkg.License
					}
				}
			}
		}
	}
	return new
}
