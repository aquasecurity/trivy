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
