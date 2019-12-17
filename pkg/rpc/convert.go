package rpc

import (
	"github.com/aquasecurity/fanal/analyzer"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/rpc/detector"
)

func ConvertToRpcPkgs(pkgs []analyzer.Package) []*detector.Package {
	var rpcPkgs []*detector.Package
	for _, pkg := range pkgs {
		rpcPkgs = append(rpcPkgs, &detector.Package{
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

func ConvertFromRpcPkgs(rpcPkgs []*detector.Package) []analyzer.Package {
	var pkgs []analyzer.Package
	for _, pkg := range rpcPkgs {
		pkgs = append(pkgs, analyzer.Package{
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

func ConvertFromRpcLibraries(rpcLibs []*detector.Library) []ptypes.Library {
	var libs []ptypes.Library
	for _, l := range rpcLibs {
		libs = append(libs, ptypes.Library{
			Name:    l.Name,
			Version: l.Version,
		})
	}
	return libs
}

func ConvertToRpcLibraries(libs []ptypes.Library) []*detector.Library {
	var rpcLibs []*detector.Library
	for _, l := range libs {
		rpcLibs = append(rpcLibs, &detector.Library{
			Name:    l.Name,
			Version: l.Version,
		})
	}
	return rpcLibs
}

func ConvertFromRpcVulns(rpcVulns []*detector.Vulnerability) []types.DetectedVulnerability {
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

func ConvertToRpcVulns(vulns []types.DetectedVulnerability) []*detector.Vulnerability {
	var rpcVulns []*detector.Vulnerability
	for _, vuln := range vulns {
		severity, err := dbTypes.NewSeverity(vuln.Severity)
		if err != nil {
			log.Logger.Warn(err)
		}

		rpcVulns = append(rpcVulns, &detector.Vulnerability{
			VulnerabilityId:  vuln.VulnerabilityID,
			PkgName:          vuln.PkgName,
			InstalledVersion: vuln.InstalledVersion,
			FixedVersion:     vuln.FixedVersion,
			Title:            vuln.Title,
			Description:      vuln.Description,
			Severity:         detector.Severity(severity),
			References:       vuln.References,
		})
	}
	return rpcVulns
}
