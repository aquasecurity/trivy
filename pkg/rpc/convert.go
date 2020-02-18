package rpc

import (
	ftypes "github.com/aquasecurity/fanal/types"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/rpc/common"
	"github.com/aquasecurity/trivy/rpc/layer"
	"github.com/aquasecurity/trivy/rpc/scanner"
)

func ConvertToRpcPkgs(pkgs []ftypes.Package) []*common.Package {
	var rpcPkgs []*common.Package
	for _, pkg := range pkgs {
		rpcPkgs = append(rpcPkgs, &common.Package{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Release:    pkg.Release,
			Epoch:      int32(pkg.Epoch),
			Arch:       pkg.Arch,
			SrcName:    pkg.SrcName,
			SrcVersion: pkg.SrcVersion,
			SrcRelease: pkg.SrcRelease,
			SrcEpoch:   int32(pkg.SrcEpoch),
		})
	}
	return rpcPkgs
}

func ConvertFromRpcPkgs(rpcPkgs []*common.Package) []ftypes.Package {
	var pkgs []ftypes.Package
	for _, pkg := range rpcPkgs {
		pkgs = append(pkgs, ftypes.Package{
			Name:       pkg.Name,
			Version:    pkg.Version,
			Release:    pkg.Release,
			Epoch:      int(pkg.Epoch),
			Arch:       pkg.Arch,
			SrcName:    pkg.SrcName,
			SrcVersion: pkg.SrcVersion,
			SrcRelease: pkg.SrcRelease,
			SrcEpoch:   int(pkg.SrcEpoch),
		})
	}
	return pkgs
}

func ConvertFromRpcLibraries(rpcLibs []*common.Library) []ptypes.Library {
	var libs []ptypes.Library
	for _, l := range rpcLibs {
		libs = append(libs, ptypes.Library{
			Name:    l.Name,
			Version: l.Version,
		})
	}
	return libs
}

func ConvertToRpcLibraries(libs []ptypes.Library) []*common.Library {
	var rpcLibs []*common.Library
	for _, l := range libs {
		rpcLibs = append(rpcLibs, &common.Library{
			Name:    l.Name,
			Version: l.Version,
		})
	}
	return rpcLibs
}

func ConvertFromRpcVulns(rpcVulns []*common.Vulnerability) []types.DetectedVulnerability {
	var vulns []types.DetectedVulnerability
	for _, vuln := range rpcVulns {
		severity := dbTypes.Severity(vuln.Severity)
		vulns = append(vulns, types.DetectedVulnerability{
			VulnerabilityID:  vuln.VulnerabilityId,
			PkgName:          vuln.PkgName,
			InstalledVersion: vuln.InstalledVersion,
			FixedVersion:     vuln.FixedVersion,
			Vulnerability: dbTypes.Vulnerability{
				Title:       vuln.Title,
				Description: vuln.Description,
				Severity:    severity.String(),
				References:  vuln.References,
			},
		})
	}
	return vulns
}

func ConvertToRpcVulns(vulns []types.DetectedVulnerability) []*common.Vulnerability {
	var rpcVulns []*common.Vulnerability
	for _, vuln := range vulns {
		severity, err := dbTypes.NewSeverity(vuln.Severity)
		if err != nil {
			log.Logger.Warn(err)
		}

		rpcVulns = append(rpcVulns, &common.Vulnerability{
			VulnerabilityId:  vuln.VulnerabilityID,
			PkgName:          vuln.PkgName,
			InstalledVersion: vuln.InstalledVersion,
			FixedVersion:     vuln.FixedVersion,
			Title:            vuln.Title,
			Description:      vuln.Description,
			Severity:         common.Severity(severity),
			References:       vuln.References,
		})
	}
	return rpcVulns
}

func ConvertFromRpcResults(rpcResults []*scanner.Result) []report.Result {
	var results []report.Result
	for _, result := range rpcResults {
		var vulns []types.DetectedVulnerability
		for _, vuln := range result.Vulnerabilities {
			severity := dbTypes.Severity(vuln.Severity)
			vulns = append(vulns, types.DetectedVulnerability{
				VulnerabilityID:  vuln.VulnerabilityId,
				PkgName:          vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				Vulnerability: dbTypes.Vulnerability{
					Title:       vuln.Title,
					Description: vuln.Description,
					Severity:    severity.String(),
					References:  vuln.References,
				},
			})
		}
		results = append(results, report.Result{
			Target:          result.Target,
			Vulnerabilities: vulns,
		})
	}
	return results
}

func ConvertFromRpcOS(rpcOS *common.OS) *ftypes.OS {
	if rpcOS == nil {
		return nil
	}
	return &ftypes.OS{
		Family: rpcOS.Family,
		Name:   rpcOS.Name,
	}
}

func ConvertFromRpcPackageInfos(rpcPkgInfos []*common.PackageInfo) []ftypes.PackageInfo {
	var pkgInfos []ftypes.PackageInfo
	for _, rpcPkgInfo := range rpcPkgInfos {
		pkgInfos = append(pkgInfos, ftypes.PackageInfo{
			FilePath: rpcPkgInfo.FilePath,
			Packages: ConvertFromRpcPkgs(rpcPkgInfo.Packages),
		})
	}
	return pkgInfos
}

func ConvertFromRpcApplications(rpcApps []*common.Application) []ftypes.Application {
	var apps []ftypes.Application
	for _, rpcApp := range rpcApps {
		apps = append(apps, ftypes.Application{
			Type:      rpcApp.Type,
			FilePath:  rpcApp.FilePath,
			Libraries: ConvertFromRpcLibraries(rpcApp.Libraries),
		})
	}
	return apps
}

func ConvertFromRpcPutRequest(putRequest *layer.PutRequest) ftypes.LayerInfo {
	return ftypes.LayerInfo{
		SchemaVersion: int(putRequest.SchemaVersion),
		OS:            ConvertFromRpcOS(putRequest.Os),
		PackageInfos:  ConvertFromRpcPackageInfos(putRequest.PackageInfos),
		Applications:  ConvertFromRpcApplications(putRequest.Applications),
		OpaqueDirs:    putRequest.OpaqueDirs,
		WhiteoutFiles: putRequest.WhiteoutFiles,
	}
}

func ConvertToRpcOS(fos *ftypes.OS) *common.OS {
	if fos == nil {
		return nil
	}
	return &common.OS{
		Family: fos.Family,
		Name:   fos.Name,
	}
}

func ConvertToRpcLayerInfo(layerID, decompressedLayerID string, layerInfo ftypes.LayerInfo) *layer.PutRequest {
	var packageInfos []*common.PackageInfo
	for _, pkgInfo := range layerInfo.PackageInfos {
		var pkgs []*common.Package
		for _, pkg := range pkgInfo.Packages {
			pkgs = append(pkgs, &common.Package{
				Name:       pkg.Name,
				Version:    pkg.Version,
				Release:    pkg.Release,
				Epoch:      int32(pkg.Epoch),
				Arch:       pkg.Arch,
				SrcName:    pkg.SrcName,
				SrcVersion: pkg.SrcVersion,
				SrcRelease: pkg.SrcRelease,
				SrcEpoch:   int32(pkg.SrcEpoch),
			})
		}
		packageInfos = append(packageInfos, &common.PackageInfo{
			FilePath: pkgInfo.FilePath,
			Packages: pkgs,
		})
	}

	var applications []*common.Application
	for _, app := range layerInfo.Applications {
		var libs []*common.Library
		for _, lib := range app.Libraries {
			libs = append(libs, &common.Library{
				Name:    lib.Name,
				Version: lib.Version,
			})

		}
		applications = append(applications, &common.Application{
			Type:      app.Type,
			FilePath:  app.FilePath,
			Libraries: libs,
		})
	}

	return &layer.PutRequest{
		LayerId:             layerID,
		DecompressedLayerId: decompressedLayerID,
		SchemaVersion:       ftypes.LayerJSONSchemaVersion,
		Os:                  ConvertToRpcOS(layerInfo.OS),
		PackageInfos:        packageInfos,
		Applications:        applications,
		OpaqueDirs:          layerInfo.OpaqueDirs,
		WhiteoutFiles:       layerInfo.WhiteoutFiles,
	}
}

func ConvertToRpcLayers(layerIDs []string) *layer.Layers {
	return &layer.Layers{
		LayerIds: layerIDs,
	}
}

func ConvertToRpcScanResponse(results report.Results, os *ftypes.OS, eosl bool) *scanner.ScanResponse {
	rpcOS := &common.OS{}
	if os != nil {
		rpcOS.Family = os.Family
		rpcOS.Name = os.Name
	}

	var rpcResults []*scanner.Result
	for _, result := range results {
		rpcResults = append(rpcResults, &scanner.Result{
			Target:          result.Target,
			Vulnerabilities: ConvertToRpcVulns(result.Vulnerabilities),
		})
	}

	return &scanner.ScanResponse{
		Os:      rpcOS,
		Eosl:    eosl,
		Results: rpcResults,
	}
}
