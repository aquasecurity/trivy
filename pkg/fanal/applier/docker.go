package applier

import (
	"cmp"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/knqyf263/nested"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
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

func findPackage(e ftypes.Package, s []ftypes.Package) *ftypes.Package {
	for i := range s {
		a := &s[i] // do not range by value to avoid heap allocations
		if a.Name == e.Name && a.Version == e.Version && a.Release == e.Release {
			return a
		}
	}
	return nil
}

func lookupOriginLayerForPkg(pkg ftypes.Package, layers []ftypes.BlobInfo) (string, string, []string, *ftypes.BuildInfo) {
	for i, layer := range layers {
		for _, info := range layer.PackageInfos {
			if p := findPackage(pkg, info.Packages); p != nil {
				return layer.Digest, layer.DiffID, p.InstalledFiles, lookupBuildInfo(i, layers)
			}
		}
	}
	return "", "", nil, nil
}

// lookupBuildInfo looks up Red Hat content sets from all layers
func lookupBuildInfo(index int, layers []ftypes.BlobInfo) *ftypes.BuildInfo {
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
	for i := index - 1; i >= 0; i-- {
		if layers[i].BuildInfo != nil {
			return layers[i].BuildInfo
		}
	}
	return nil
}

func lookupOriginLayerForLib(filePath string, lib ftypes.Package, layers []ftypes.BlobInfo) (string, string) {
	for _, layer := range layers {
		for _, layerApp := range layer.Applications {
			if filePath != layerApp.FilePath {
				continue
			}
			if findPackage(lib, layerApp.Packages) != nil {
				return layer.Digest, layer.DiffID
			}
		}
	}
	return "", ""
}

func lookupOriginLayerForCustomResource(customResource ftypes.CustomResource, layers []ftypes.BlobInfo) (string, string) {
	for _, layer := range layers {
		for _, layerCR := range layer.CustomResources {
			if customResource.FilePath != layerCR.FilePath || customResource.Type != layerCR.Type {
				continue
			}
			return layer.Digest, layer.DiffID
		}
	}
	return "", ""
}

// ApplyLayers returns the merged layer
// nolint: gocyclo
func ApplyLayers(layers []ftypes.BlobInfo) ftypes.ArtifactDetail {
	sep := "/"
	nestedMap := nested.Nested{}
	applications := make(map[string]ftypes.Application)
	applicationKeysByFilePath := make(map[string]map[string]struct{})
	sbomApplicationKeysByPackageFilePath := make(map[string]map[string]struct{})
	secretsMap := make(map[string]ftypes.Secret)
	var mergedLayer ftypes.ArtifactDetail

	for _, layer := range layers {
		for _, opqDir := range layer.OpaqueDirs {
			opqDir = strings.TrimSuffix(opqDir, sep)  // this is necessary so that an empty element is not contribute into the array of the DeleteByString function
			_ = nestedMap.DeleteByString(opqDir, sep) // nolint
			deleteApplications(applications, applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, opqDir, sep)
		}
		for _, whFile := range layer.WhiteoutFiles {
			_ = nestedMap.DeleteByString(whFile, sep) // nolint
			deleteApplications(applications, applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, whFile, sep)
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
			setApplication(nestedMap, applications, applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, app, sep)
		}

		// Apply misconfigurations
		for _, config := range layer.Misconfigurations {
			config.Layer = ftypes.Layer{
				Digest: layer.Digest,
				DiffID: layer.DiffID,
			}
			key := fmt.Sprintf("%s/type:config", config.FilePath)
			nestedMap.SetByString(key, sep, config)
		}

		// Apply secrets
		for _, secret := range layer.Secrets {
			l := ftypes.Layer{
				Digest:    layer.Digest,
				DiffID:    layer.DiffID,
				CreatedBy: layer.CreatedBy,
			}
			secretsMap = mergeSecrets(secretsMap, secret, l)
		}

		// Apply license files
		for _, license := range layer.Licenses {
			license.Layer = ftypes.Layer{
				Digest: layer.Digest,
				DiffID: layer.DiffID,
			}
			key := fmt.Sprintf("%s/type:license,%s", license.FilePath, license.Type)
			nestedMap.SetByString(key, sep, license)
		}

		// Apply custom resources
		for _, customResource := range layer.CustomResources {
			key := fmt.Sprintf("%s/custom:%s", customResource.FilePath, customResource.Type)
			nestedMap.SetByString(key, sep, customResource)
		}
	}

	// nolint
	_ = nestedMap.Walk(func(keys []string, value any) error {
		switch v := value.(type) {
		case ftypes.PackageInfo:
			mergedLayer.Packages = append(mergedLayer.Packages, v.Packages...)
		case ftypes.Application:
			mergedLayer.Applications = append(mergedLayer.Applications, v)
		case ftypes.Misconfiguration:
			mergedLayer.Misconfigurations = append(mergedLayer.Misconfigurations, v)
		case ftypes.LicenseFile:
			mergedLayer.Licenses = append(mergedLayer.Licenses, v)
		case ftypes.CustomResource:
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
	dpkgLicenses := make(map[string][]string)
	mergedLayer.Licenses = lo.Reject(mergedLayer.Licenses, func(license ftypes.LicenseFile, _ int) bool {
		if license.Type != ftypes.LicenseTypeDpkg {
			return false
		}
		// e.g.
		//	"adduser" => {"GPL-2"}
		//  "openssl" => {"MIT", "BSD"}
		dpkgLicenses[license.PkgName] = xslices.Map(license.Findings, func(finding ftypes.LicenseFinding) string {
			return finding.Name
		})
		// Remove this license in the merged result as it is merged into the package information.
		return true
	})
	if len(mergedLayer.Licenses) == 0 {
		mergedLayer.Licenses = nil
	}

	for i, pkg := range mergedLayer.Packages {
		// Skip lookup for SBOMs obtained from container images (pkg.Layer is already set).
		if lo.IsEmpty(pkg.Layer) {
			originLayerDigest, originLayerDiffID, installedFiles, buildInfo := lookupOriginLayerForPkg(pkg, layers)
			mergedLayer.Packages[i].Layer = ftypes.Layer{
				Digest: originLayerDigest,
				DiffID: originLayerDiffID,
			}
			// Do not overwrite BuildInfo if it is already set (e.g. packages from SBOMs generated by trivy rootfs).
			if buildInfo != nil {
				mergedLayer.Packages[i].BuildInfo = buildInfo
			}
			// Debian/Ubuntu has the installed files only in the first layer where the package is installed.
			mergedLayer.Packages[i].InstalledFiles = installedFiles
		}

		if mergedLayer.OS.Family != "" && pkg.Identifier.PURL == nil {
			mergedLayer.Packages[i].Identifier.PURL = newPURL(mergedLayer.OS.Family, types.Metadata{OS: &mergedLayer.OS}, pkg)
		}
		mergedLayer.Packages[i].Identifier.UID = dependency.UID("", pkg)

		// Only debian packages
		if licenses, ok := dpkgLicenses[pkg.Name]; ok {
			mergedLayer.Packages[i].Licenses = licenses
		}
	}

	// Filter OS packages with mismatched PURL namespace
	mergedLayer.Packages = filterMismatchedOSPkgs(mergedLayer.OS.Family, mergedLayer.Packages)

	// If an image contains embedded per-package SBOMs (e.g. Chainguard/Wolfi
	// /var/lib/db/sbom/*.spdx.json), both the OS package-DB analyzer (apk/dpkg/rpm) and
	// the SBOM analyzer report the same OS package, colliding on the same dedup key.
	// To get a deterministic result, we sort packages before the deduplication below,
	// giving packages from the OS package managers priority, because:
	//   1. SBOM-derived packages may carry less complete metadata (e.g. missing source
	//      info, so SrcName falls back to Name).
	//   2. package-manager DB files are standardized and hold authoritative package
	//      info (e.g. source/origin from apk o: / dpkg Source: / rpm source RPM).
	// cf. https://github.com/aquasecurity/trivy/issues/10778
	slices.SortStableFunc(mergedLayer.Packages, func(a, b ftypes.Package) int {
		switch {
		case a.AnalyzedBy == b.AnalyzedBy:
			return 0
		case a.AnalyzedBy == analyzer.TypeSBOM:
			return 1
		case b.AnalyzedBy == analyzer.TypeSBOM:
			return -1
		default:
			return 0
		}
	})

	// De-duplicate same debian packages from different dirs
	// cf. https://github.com/aquasecurity/trivy/issues/8297
	mergedLayer.Packages = xslices.ZeroToNil(lo.UniqBy(mergedLayer.Packages, func(pkg ftypes.Package) string {
		id := cmp.Or(pkg.ID, fmt.Sprintf("%s@%s", pkg.Name, utils.FormatVersion(pkg)))
		// To avoid deduplicating packages with the same ID but from different locations (e.g. RPM archives), check the file path.
		return fmt.Sprintf("%s/%s", id, pkg.FilePath)
	}))

	for _, app := range mergedLayer.Applications {
		for i, pkg := range app.Packages {
			// Skip lookup for SBOM
			if lo.IsEmpty(pkg.Layer) {
				originLayerDigest, originLayerDiffID := lookupOriginLayerForLib(app.FilePath, pkg, layers)
				app.Packages[i].Layer = ftypes.Layer{
					Digest: originLayerDigest,
					DiffID: originLayerDiffID,
				}
			}
			if pkg.Identifier.PURL == nil {
				app.Packages[i].Identifier.PURL = newPURL(app.Type, types.Metadata{}, pkg)
			}
			app.Packages[i].Identifier.UID = dependency.UID(app.FilePath, pkg)
		}
	}

	for i, customResource := range mergedLayer.CustomResources {
		// Skip lookup if the layer is already set.
		if lo.IsEmpty(customResource.Layer) {
			originLayerDigest, originLayerDiffID := lookupOriginLayerForCustomResource(customResource, layers)
			mergedLayer.CustomResources[i].Layer = ftypes.Layer{
				Digest: originLayerDigest,
				DiffID: originLayerDiffID,
			}
		}
	}

	// Aggregate python/ruby/node.js packages and JAR files
	aggregate(&mergedLayer)

	mergedLayer.Sort()

	return mergedLayer
}

func setApplication(nestedMap nested.Nested, applications map[string]ftypes.Application, applicationKeysByFilePath,
	sbomApplicationKeysByPackageFilePath map[string]map[string]struct{}, app ftypes.Application, sep string) {
	existingKey, existing, ok := findMergeableApplication(applications, applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, app)
	if !ok {
		setApplicationByKey(nestedMap, applications, applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, app, sep)
		return
	}

	merged := mergeApplications(existing, app)
	mergedKey := applicationKey(merged)
	if existingKey != mergedKey {
		deleteApplicationByKey(nestedMap, applications, applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, existingKey, sep)
	}
	setApplicationByKey(nestedMap, applications, applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, merged, sep)
}

func applicationKey(app ftypes.Application) string {
	return fmt.Sprintf("%s/type:%s", app.FilePath, app.Type)
}

func findMergeableApplication(applications map[string]ftypes.Application, applicationKeysByFilePath,
	sbomApplicationKeysByPackageFilePath map[string]map[string]struct{}, app ftypes.Application) (string, ftypes.Application, bool) {
	if isSBOMApplication(app) {
		return findApplicationCoveredBySBOM(applications, applicationKeysByFilePath, app)
	}
	return findSBOMApplicationCoveringFilePath(applications, sbomApplicationKeysByPackageFilePath, app.FilePath)
}

func findApplicationCoveredBySBOM(applications map[string]ftypes.Application, applicationKeysByFilePath map[string]map[string]struct{},
	app ftypes.Application) (string, ftypes.Application, bool) {
	for _, pkg := range app.Packages {
		if pkg.FilePath == "" {
			continue
		}
		if appKey, app, ok := findApplicationByFilePath(applications, applicationKeysByFilePath, pkg.FilePath, false); ok {
			return appKey, app, true
		}
	}
	return "", ftypes.Application{}, false
}

func findSBOMApplicationCoveringFilePath(applications map[string]ftypes.Application, sbomApplicationKeysByPackageFilePath map[string]map[string]struct{},
	filePath string) (string, ftypes.Application, bool) {
	if filePath == "" {
		return "", ftypes.Application{}, false
	}
	appKeys := sortedApplicationKeys(sbomApplicationKeysByPackageFilePath[filePath])
	for _, appKey := range appKeys {
		app, ok := applications[appKey]
		if ok && isSBOMApplication(app) {
			return appKey, app, true
		}
	}
	return "", ftypes.Application{}, false
}

func findApplicationByFilePath(applications map[string]ftypes.Application, applicationKeysByFilePath map[string]map[string]struct{},
	filePath string, sbom bool) (string, ftypes.Application, bool) {
	appKeys := sortedApplicationKeys(applicationKeysByFilePath[filePath])
	for _, appKey := range appKeys {
		app, ok := applications[appKey]
		if ok && isSBOMApplication(app) == sbom {
			return appKey, app, true
		}
	}
	return "", ftypes.Application{}, false
}

func sortedApplicationKeys(applicationKeys map[string]struct{}) []string {
	keys := make([]string, 0, len(applicationKeys))
	for key := range applicationKeys {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

func setApplicationByKey(nestedMap nested.Nested, applications map[string]ftypes.Application, applicationKeysByFilePath,
	sbomApplicationKeysByPackageFilePath map[string]map[string]struct{}, app ftypes.Application, sep string) {
	appKey := applicationKey(app)
	if existing, ok := applications[appKey]; ok {
		deleteApplicationIndexes(applications, applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, appKey, existing)
	}
	nestedMap.SetByString(appKey, sep, app)
	applications[appKey] = app
	addApplicationIndexes(applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, appKey, app)
}

func deleteApplications(applications map[string]ftypes.Application, applicationKeysByFilePath,
	sbomApplicationKeysByPackageFilePath map[string]map[string]struct{}, filePath, sep string) {
	if filePath == "" {
		return
	}
	for appKey, app := range applications {
		if appKey == filePath || strings.HasPrefix(appKey, filePath+sep) {
			deleteApplicationIndexes(applications, applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, appKey, app)
		}
	}
}

func deleteApplicationByKey(nestedMap nested.Nested, applications map[string]ftypes.Application, applicationKeysByFilePath,
	sbomApplicationKeysByPackageFilePath map[string]map[string]struct{}, appKey, sep string) {
	if app, ok := applications[appKey]; ok {
		deleteApplicationIndexes(applications, applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath, appKey, app)
	}
	_ = nestedMap.DeleteByString(appKey, sep) // nolint
}

func addApplicationIndexes(applicationKeysByFilePath, sbomApplicationKeysByPackageFilePath map[string]map[string]struct{},
	appKey string, app ftypes.Application) {
	addApplicationIndex(applicationKeysByFilePath, app.FilePath, appKey)
	if !isSBOMApplication(app) {
		return
	}
	for _, pkg := range app.Packages {
		addApplicationIndex(sbomApplicationKeysByPackageFilePath, pkg.FilePath, appKey)
	}
}

func deleteApplicationIndexes(applications map[string]ftypes.Application, applicationKeysByFilePath,
	sbomApplicationKeysByPackageFilePath map[string]map[string]struct{}, appKey string, app ftypes.Application) {
	delete(applications, appKey)
	deleteApplicationIndex(applicationKeysByFilePath, app.FilePath, appKey)
	if !isSBOMApplication(app) {
		return
	}
	for _, pkg := range app.Packages {
		deleteApplicationIndex(sbomApplicationKeysByPackageFilePath, pkg.FilePath, appKey)
	}
}

func addApplicationIndex(index map[string]map[string]struct{}, filePath, appKey string) {
	if filePath == "" {
		return
	}
	if index[filePath] == nil {
		index[filePath] = make(map[string]struct{})
	}
	index[filePath][appKey] = struct{}{}
}

func deleteApplicationIndex(index map[string]map[string]struct{}, filePath, appKey string) {
	if filePath == "" {
		return
	}
	delete(index[filePath], appKey)
	if len(index[filePath]) == 0 {
		delete(index, filePath)
	}
}

func mergeApplications(a, b ftypes.Application) ftypes.Application {
	if isSBOMApplication(a) && !isSBOMApplication(b) {
		a, b = b, a
	}
	a.Packages = mergeApplicationPackages(a.Type, a.Packages, b.Packages)
	return a
}

func mergeApplicationPackages(appType ftypes.LangType, pkgs, extra ftypes.Packages) ftypes.Packages {
	merged := slices.Clone(pkgs)
	for _, pkg := range extra {
		if slices.ContainsFunc(merged, func(existing ftypes.Package) bool {
			return reflect.DeepEqual(existing, pkg)
		}) {
			continue
		}

		identity := packageIdentity(appType, pkg)
		index := slices.IndexFunc(merged, func(existing ftypes.Package) bool {
			return identity != "" && packageIdentity(appType, existing) == identity
		})
		if index == -1 {
			merged = append(merged, pkg)
			continue
		}
		if merged[index].AnalyzedBy == analyzer.TypeSBOM && pkg.AnalyzedBy != analyzer.TypeSBOM {
			merged[index] = pkg
		}
	}
	return xslices.ZeroToNil(merged)
}

func packageIdentity(appType ftypes.LangType, pkg ftypes.Package) string {
	name := pkg.Name
	version := pkg.Version
	if pkg.Identifier.PURL != nil {
		name = cmp.Or(name, pkg.Identifier.PURL.Name)
		version = cmp.Or(version, pkg.Identifier.PURL.Version)
	}
	name = cmp.Or(name, pkg.ID)
	if name == "" {
		return ""
	}
	version = normalizePackageVersion(appType, version)
	return fmt.Sprintf("%s/%s/%s/%s/%s/%d", appType, name, version, pkg.Release, pkg.Arch, pkg.Epoch)
}

func normalizePackageVersion(appType ftypes.LangType, version string) string {
	if (appType == ftypes.GoBinary || appType == ftypes.GoModule) &&
		len(version) > 1 && version[0] == 'v' && version[1] >= '0' && version[1] <= '9' {
		return version[1:]
	}
	return version
}

func isSBOMApplication(app ftypes.Application) bool {
	if isSBOMFilePath(app.FilePath) {
		return true
	}
	if len(app.Packages) == 0 {
		return false
	}
	return lo.EveryBy(app.Packages, func(pkg ftypes.Package) bool {
		return pkg.AnalyzedBy == analyzer.TypeSBOM
	})
}

func isSBOMFilePath(filePath string) bool {
	return strings.HasSuffix(filePath, ".spdx") ||
		strings.HasSuffix(filePath, ".spdx.json") ||
		strings.HasSuffix(filePath, ".cdx") ||
		strings.HasSuffix(filePath, ".cdx.json")
}

func newPURL(pkgType ftypes.TargetType, metadata types.Metadata, pkg ftypes.Package) *packageurl.PackageURL {
	// Possible cases when package doesn't have name/version (e.g. local package.json).
	// For these cases we don't need to create PURL, because this PURL will be incorrect.
	// TODO Dmitriy - move to `purl` package
	if pkg.Name == "" {
		return nil
	}

	p, err := purl.New(pkgType, metadata, pkg)
	if err != nil {
		log.Error("Failed to create PackageURL", log.Err(err))
		return nil
	}
	return p.Unwrap()
}

// aggregate merges all packages installed by pip/gem/npm/jar/conda into each application
func aggregate(detail *ftypes.ArtifactDetail) {
	var apps []ftypes.Application

	aggregatedApps := make(map[ftypes.LangType]*ftypes.Application)
	for _, t := range ftypes.AggregatingTypes {
		aggregatedApps[t] = &ftypes.Application{Type: t}
	}

	for _, app := range detail.Applications {
		a, ok := aggregatedApps[app.Type]
		if !ok {
			apps = append(apps, app)
			continue
		}
		a.Packages = append(a.Packages, app.Packages...)
	}

	for _, app := range aggregatedApps {
		if len(app.Packages) > 0 {
			apps = append(apps, *app)
		}
	}

	// Overwrite Applications
	detail.Applications = apps
}

// We must save secrets from all layers even though they are removed in the uppler layer.
// If the secret was changed at the top level, we need to overwrite it.
func mergeSecrets(secretsMap map[string]ftypes.Secret, newSecret ftypes.Secret, layer ftypes.Layer) map[string]ftypes.Secret {
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

func secretFindingsContains(findings []ftypes.SecretFinding, finding ftypes.SecretFinding) bool {
	for _, f := range findings {
		if f.RuleID == finding.RuleID {
			return true
		}
	}
	return false
}

// purlMatchesOS checks if a package's PURL namespace matches the detected OS family.
// Returns true if the package should be kept (matches OS or has no PURL/namespace).
// Returns false if the package should be filtered out (has PURL with mismatched namespace).
func purlMatchesOS(pkg ftypes.Package, osFamily ftypes.OSType) bool {
	if pkg.Identifier.PURL == nil || osFamily == "" {
		return true // Keep packages without PURL or when OS is not detected
	}
	if pkg.Identifier.PURL.Namespace == "" {
		return true // Keep packages without namespace
	}
	return pkg.Identifier.PURL.Namespace == osFamily.PurlNamespace()
}

// filterMismatchedOSPkgs removes OS packages whose PURL namespace doesn't match the detected OS.
// Packages with pre-existing PURLs are typically from SBOM files embedded in the image.
func filterMismatchedOSPkgs(osFamily ftypes.OSType, pkgs ftypes.Packages) ftypes.Packages {
	if osFamily == "" {
		return pkgs // No OS detected, keep all packages
	}

	var filtered int
	result := lo.Filter(pkgs, func(pkg ftypes.Package, _ int) bool {
		if purlMatchesOS(pkg, osFamily) {
			return true
		}
		filtered++
		return false
	})

	if filtered > 0 {
		log.WithPrefix("applier").Warn("Some OS packages were skipped due to mismatched PURL namespace",
			log.Int("pkg_count", filtered),
			log.String("detected_os", string(osFamily)))
	}

	return result
}
