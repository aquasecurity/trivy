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
		cvssMap := make(map[string]*common.CVSS) // This is needed because protobuf generates a map[string]*CVSS type
		for vendor, vendorSeverity := range vuln.CVSS {
			cvssMap[vendor] = &common.CVSS{
				V2Vector: vendorSeverity.V2Vector,
				V3Vector: vendorSeverity.V3Vector,
				V2Score:  vendorSeverity.V2Score,
				V3Score:  vendorSeverity.V3Score,
			}
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
			Cvss:           cvssMap,
			SeveritySource: vuln.SeveritySource,
			CweIds:         vuln.CweIDs,
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
			cvssMap := make(dbTypes.VendorCVSS) // This is needed because protobuf generates a map[string]*CVSS type
			for vendor, vendorSeverity := range vuln.Cvss {
				cvssMap[vendor] = dbTypes.CVSS{
					V2Vector: vendorSeverity.V2Vector,
					V3Vector: vendorSeverity.V3Vector,
					V2Score:  vendorSeverity.V2Score,
					V3Score:  vendorSeverity.V3Score,
				}
			}

			vulns = append(vulns, types.DetectedVulnerability{
				VulnerabilityID:  vuln.VulnerabilityId,
				PkgName:          vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				Vulnerability: dbTypes.Vulnerability{
					Title:       vuln.Title,
					Description: vuln.Description,
					Severity:    severity.String(),
					CVSS:        cvssMap,
					References:  vuln.References,
					CweIDs:      vuln.CweIds,
				},
				Layer: ftypes.Layer{
					Digest: vuln.Layer.Digest,
					DiffID: vuln.Layer.DiffId,
				},
				SeveritySource: vuln.SeveritySource,
			})
		}
		results = append(results, report.Result{
			Target:          result.Target,
			Vulnerabilities: vulns,
			Type:            result.Type,
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

func ConvertFromRpcPutArtifactRequest(req *cache.PutArtifactRequest) ftypes.ArtifactInfo {
	created, _ := ptypes.Timestamp(req.ArtifactInfo.Created)
	return ftypes.ArtifactInfo{
		SchemaVersion:   int(req.ArtifactInfo.SchemaVersion),
		Architecture:    req.ArtifactInfo.Architecture,
		Created:         created,
		DockerVersion:   req.ArtifactInfo.DockerVersion,
		OS:              req.ArtifactInfo.Os,
		HistoryPackages: ConvertFromRpcPkgs(req.ArtifactInfo.HistoryPackages),
	}
}

func ConvertFromRpcPutBlobRequest(req *cache.PutBlobRequest) ftypes.BlobInfo {
	return ftypes.BlobInfo{
		SchemaVersion: int(req.BlobInfo.SchemaVersion),
		Digest:        req.BlobInfo.Digest,
		DiffID:        req.BlobInfo.DiffId,
		OS:            ConvertFromRpcOS(req.BlobInfo.Os),
		PackageInfos:  ConvertFromRpcPackageInfos(req.BlobInfo.PackageInfos),
		Applications:  ConvertFromRpcApplications(req.BlobInfo.Applications),
		OpaqueDirs:    req.BlobInfo.OpaqueDirs,
		WhiteoutFiles: req.BlobInfo.WhiteoutFiles,
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

func ConvertToRpcArtifactInfo(imageID string, imageInfo ftypes.ArtifactInfo) *cache.PutArtifactRequest {
	t, err := ptypes.TimestampProto(imageInfo.Created)
	if err != nil {
		log.Logger.Warnf("invalid timestamp: %s", err)
	}

	return &cache.PutArtifactRequest{
		ArtifactId: imageID,
		ArtifactInfo: &cache.ArtifactInfo{
			SchemaVersion:   int32(imageInfo.SchemaVersion),
			Architecture:    imageInfo.Architecture,
			Created:         t,
			DockerVersion:   imageInfo.DockerVersion,
			Os:              imageInfo.OS,
			HistoryPackages: ConvertToRpcPkgs(imageInfo.HistoryPackages),
		},
	}
}

func ConvertToRpcBlobInfo(diffID string, layerInfo ftypes.BlobInfo) *cache.PutBlobRequest {
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

	return &cache.PutBlobRequest{
		DiffId: diffID,
		BlobInfo: &cache.BlobInfo{
			SchemaVersion: ftypes.BlobJSONSchemaVersion,
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

func ConvertToMissingBlobsRequest(imageID string, layerIDs []string) *cache.MissingBlobsRequest {
	return &cache.MissingBlobsRequest{
		ArtifactId: imageID,
		BlobIds:    layerIDs,
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
			Type:            result.Type,
		})
	}

	return &scanner.ScanResponse{
		Os:      rpcOS,
		Eosl:    eosl,
		Results: rpcResults,
	}
}
