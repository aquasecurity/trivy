package rpc

import (
	"github.com/golang/protobuf/ptypes"

	ftypes "github.com/aquasecurity/fanal/types"
	deptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/rpc/cache"
	"github.com/aquasecurity/trivy/rpc/common"
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

func ConvertFromRpcLibraries(rpcLibs []*common.Library) []ftypes.LibraryInfo {
	var libs []ftypes.LibraryInfo
	for _, l := range rpcLibs {
		libs = append(libs, ftypes.LibraryInfo{
			Library: deptypes.Library{
				Name:    l.Name,
				Version: l.Version,
			},
		})
	}
	return libs
}

func ConvertToRpcLibraries(libs []deptypes.Library) []*common.Library {
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
			Layer: &common.Layer{
				Digest: vuln.Layer.Digest,
				DiffId: vuln.Layer.DiffID,
			},
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
				Layer: ftypes.Layer{
					Digest: vuln.Layer.Digest,
					DiffID: vuln.Layer.DiffId,
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

func ConvertFromRpcPutImageRequest(req *cache.PutImageRequest) ftypes.ImageInfo {
	created, _ := ptypes.Timestamp(req.ImageInfo.Created)
	return ftypes.ImageInfo{
		SchemaVersion:   int(req.ImageInfo.SchemaVersion),
		Architecture:    req.ImageInfo.Architecture,
		Created:         created,
		DockerVersion:   req.ImageInfo.DockerVersion,
		OS:              req.ImageInfo.Os,
		HistoryPackages: ConvertFromRpcPkgs(req.ImageInfo.HistoryPackages),
	}
}

func ConvertFromRpcPutLayerRequest(req *cache.PutLayerRequest) ftypes.LayerInfo {
	return ftypes.LayerInfo{
		SchemaVersion: int(req.LayerInfo.SchemaVersion),
		Digest:        req.LayerInfo.Digest,
		DiffID:        req.LayerInfo.DiffId,
		OS:            ConvertFromRpcOS(req.LayerInfo.Os),
		PackageInfos:  ConvertFromRpcPackageInfos(req.LayerInfo.PackageInfos),
		Applications:  ConvertFromRpcApplications(req.LayerInfo.Applications),
		OpaqueDirs:    req.LayerInfo.OpaqueDirs,
		WhiteoutFiles: req.LayerInfo.WhiteoutFiles,
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

func ConvertToRpcImageInfo(imageID string, imageInfo ftypes.ImageInfo) *cache.PutImageRequest {
	t, err := ptypes.TimestampProto(imageInfo.Created)
	if err != nil {
		log.Logger.Warnf("invalid timestamp: %s", err)
	}

	return &cache.PutImageRequest{
		ImageId: imageID,
		ImageInfo: &cache.ImageInfo{
			SchemaVersion:   int32(imageInfo.SchemaVersion),
			Architecture:    imageInfo.Architecture,
			Created:         t,
			DockerVersion:   imageInfo.DockerVersion,
			Os:              imageInfo.OS,
			HistoryPackages: ConvertToRpcPkgs(imageInfo.HistoryPackages),
		},
	}
}

func ConvertToRpcLayerInfo(diffID string, layerInfo ftypes.LayerInfo) *cache.PutLayerRequest {
	var packageInfos []*common.PackageInfo
	for _, pkgInfo := range layerInfo.PackageInfos {
		packageInfos = append(packageInfos, &common.PackageInfo{
			FilePath: pkgInfo.FilePath,
			Packages: ConvertToRpcPkgs(pkgInfo.Packages),
		})
	}

	var applications []*common.Application
	for _, app := range layerInfo.Applications {
		var libs []*common.Library
		for _, lib := range app.Libraries {
			libs = append(libs, &common.Library{
				Name:    lib.Library.Name,
				Version: lib.Library.Version,
			})

		}
		applications = append(applications, &common.Application{
			Type:      app.Type,
			FilePath:  app.FilePath,
			Libraries: libs,
		})
	}

	return &cache.PutLayerRequest{
		DiffId: diffID,
		LayerInfo: &cache.LayerInfo{
			SchemaVersion: ftypes.LayerJSONSchemaVersion,
			Digest:        layerInfo.Digest,
			DiffId:        layerInfo.DiffID,
			Os:            ConvertToRpcOS(layerInfo.OS),
			PackageInfos:  packageInfos,
			Applications:  applications,
			OpaqueDirs:    layerInfo.OpaqueDirs,
			WhiteoutFiles: layerInfo.WhiteoutFiles,
		},
	}
}

func ConvertToMissingLayersRequest(imageID string, layerIDs []string) *cache.MissingLayersRequest {
	return &cache.MissingLayersRequest{
		ImageId:  imageID,
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
