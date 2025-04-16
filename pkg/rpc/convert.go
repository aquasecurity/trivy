package rpc

import (
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/rpc/cache"
	"github.com/aquasecurity/trivy/rpc/common"
	"github.com/aquasecurity/trivy/rpc/scanner"
)

var LicenseCategoryMap = map[common.LicenseCategory_Enum]ftypes.LicenseCategory{
	common.LicenseCategory_UNSPECIFIED:  "",
	common.LicenseCategory_FORBIDDEN:    ftypes.CategoryForbidden,
	common.LicenseCategory_RESTRICTED:   ftypes.CategoryRestricted,
	common.LicenseCategory_RECIPROCAL:   ftypes.CategoryReciprocal,
	common.LicenseCategory_NOTICE:       ftypes.CategoryNotice,
	common.LicenseCategory_PERMISSIVE:   ftypes.CategoryPermissive,
	common.LicenseCategory_UNENCUMBERED: ftypes.CategoryUnencumbered,
	common.LicenseCategory_UNKNOWN:      ftypes.CategoryUnknown,
}

var LicenseTypeMap = map[common.LicenseType_Enum]ftypes.LicenseType{
	common.LicenseType_UNSPECIFIED:  "",
	common.LicenseType_DPKG:         ftypes.LicenseTypeDpkg,
	common.LicenseType_HEADER:       ftypes.LicenseTypeHeader,
	common.LicenseType_LICENSE_FILE: ftypes.LicenseTypeFile,
}

// ByValueOr returns the key from the map of the first matched value,
// or default key if the value is not present.
func ByValueOr[K, V comparable](m map[K]V, val V, d K) K {
	for k, v := range m {
		if v == val {
			return k
		}
	}
	return d
}

// ConvertToRPCPkgs returns the list of RPC package objects
func ConvertToRPCPkgs(pkgs []ftypes.Package) []*common.Package {
	var rpcPkgs []*common.Package
	for _, pkg := range pkgs {
		rpcPkgs = append(rpcPkgs, &common.Package{
			Id:         pkg.ID,
			Name:       pkg.Name,
			Version:    pkg.Version,
			Release:    pkg.Release,
			Epoch:      int32(pkg.Epoch),
			Arch:       pkg.Arch,
			Identifier: ConvertToRPCPkgIdentifier(pkg.Identifier),
			Dev:        pkg.Dev,
			SrcName:    pkg.SrcName,
			SrcVersion: pkg.SrcVersion,
			SrcRelease: pkg.SrcRelease,
			SrcEpoch:   int32(pkg.SrcEpoch),
			Licenses:   pkg.Licenses,
			Locations:  ConvertToRPCLocations(pkg.Locations),
			Layer:      ConvertToRPCLayer(pkg.Layer),
			FilePath:   pkg.FilePath,
			DependsOn:  pkg.DependsOn,
			Digest:     pkg.Digest.String(),
			Indirect:   pkg.Indirect,
			Maintainer: pkg.Maintainer,
		})
	}
	return rpcPkgs
}

func ConvertToRPCPkgIdentifier(pkg ftypes.PkgIdentifier) *common.PkgIdentifier {
	if pkg.Empty() {
		return nil
	}

	var p string
	if pkg.PURL != nil {
		p = pkg.PURL.String()
	}
	return &common.PkgIdentifier{
		Uid:    pkg.UID,
		Purl:   p,
		BomRef: pkg.BOMRef,
	}
}

func ConvertToRPCLocations(pkgLocs []ftypes.Location) []*common.Location {
	var locations []*common.Location
	for _, pkgLoc := range pkgLocs {
		locations = append(locations, &common.Location{
			StartLine: int32(pkgLoc.StartLine),
			EndLine:   int32(pkgLoc.EndLine),
		})
	}
	return locations
}

func ConvertToRPCCustomResources(resources []ftypes.CustomResource) []*common.CustomResource {
	var rpcResources []*common.CustomResource
	for _, r := range resources {
		data, err := structpb.NewValue(r.Data)
		if err != nil {
			log.Warn("Custom resource conversion error", log.Err(err))
		}
		rpcResources = append(rpcResources, &common.CustomResource{
			Type:     r.Type,
			FilePath: r.FilePath,
			Layer: &common.Layer{
				Digest: r.Layer.Digest,
				DiffId: r.Layer.DiffID,
			},
			Data: data,
		})
	}
	return rpcResources
}

func ConvertToRPCCode(code ftypes.Code) *common.Code {
	var rpcLines []*common.Line
	for _, line := range code.Lines {
		rpcLines = append(rpcLines, &common.Line{
			Number:      int32(line.Number),
			Content:     line.Content,
			IsCause:     line.IsCause,
			Annotation:  line.Annotation,
			Truncated:   line.Truncated,
			Highlighted: line.Highlighted,
			FirstCause:  line.FirstCause,
			LastCause:   line.LastCause,
		})
	}
	return &common.Code{
		Lines: rpcLines,
	}
}

func ConvertToRPCSecrets(secrets []ftypes.Secret) []*common.Secret {
	var rpcSecrets []*common.Secret
	for _, s := range secrets {
		rpcSecrets = append(rpcSecrets, ConvertToRPCSecret(&s))
	}
	return rpcSecrets
}

func ConvertToRPCSecretFindings(findings []ftypes.SecretFinding) []*common.SecretFinding {
	var rpcFindings []*common.SecretFinding
	for _, f := range findings {
		rpcFindings = append(rpcFindings, &common.SecretFinding{
			RuleId:    f.RuleID,
			Category:  string(f.Category),
			Severity:  f.Severity,
			Title:     f.Title,
			EndLine:   int32(f.EndLine),
			StartLine: int32(f.StartLine),
			Code:      ConvertToRPCCode(f.Code),
			Match:     f.Match,
			Layer:     ConvertToRPCLayer(f.Layer),
		})
	}
	return rpcFindings
}

func ConvertToRPCLicenseFiles(licenses []ftypes.LicenseFile) []*common.LicenseFile {
	var rpcLicenses []*common.LicenseFile

	for _, lic := range licenses {
		rpcLicenses = append(rpcLicenses, &common.LicenseFile{
			LicenseType: ConvertToRPCLicenseType(lic.Type),
			FilePath:    lic.FilePath,
			PkgName:     lic.PkgName,
			Fingings:    ConvertToRPCLicenseFindings(lic.Findings),
			Layer:       ConvertToRPCLayer(lic.Layer),
		})
	}

	return rpcLicenses
}

func ConvertToRPCLicenseFindings(findings ftypes.LicenseFindings) []*common.LicenseFinding {
	var rpcFindings []*common.LicenseFinding

	for _, f := range findings {
		rpcFindings = append(rpcFindings, &common.LicenseFinding{
			Category:   ConvertToRPCLicenseCategory(f.Category),
			Name:       f.Name,
			Confidence: float32(f.Confidence),
			Link:       f.Link,
		})
	}

	return rpcFindings
}

// ConvertFromRPCPkgs returns list of Fanal package objects
func ConvertFromRPCPkgs(rpcPkgs []*common.Package) []ftypes.Package {
	var pkgs []ftypes.Package
	for _, pkg := range rpcPkgs {
		pkgs = append(pkgs, ftypes.Package{
			ID:         pkg.Id,
			Name:       pkg.Name,
			Version:    pkg.Version,
			Release:    pkg.Release,
			Epoch:      int(pkg.Epoch),
			Arch:       pkg.Arch,
			Identifier: ConvertFromRPCPkgIdentifier(pkg.Identifier),
			Dev:        pkg.Dev,
			SrcName:    pkg.SrcName,
			SrcVersion: pkg.SrcVersion,
			SrcRelease: pkg.SrcRelease,
			SrcEpoch:   int(pkg.SrcEpoch),
			Licenses:   pkg.Licenses,
			Locations:  ConvertFromRPCLocation(pkg.Locations),
			Layer:      ConvertFromRPCLayer(pkg.Layer),
			FilePath:   pkg.FilePath,
			DependsOn:  pkg.DependsOn,
			Digest:     digest.Digest(pkg.Digest),
			Indirect:   pkg.Indirect,
			Maintainer: pkg.Maintainer,
		})
	}
	return pkgs
}

func ConvertFromRPCPkgIdentifier(pkg *common.PkgIdentifier) ftypes.PkgIdentifier {
	if pkg == nil {
		return ftypes.PkgIdentifier{}
	}

	pkgID := ftypes.PkgIdentifier{
		UID:    pkg.GetUid(),
		BOMRef: pkg.GetBomRef(),
	}

	if pkg.Purl != "" {
		pu, err := packageurl.FromString(pkg.Purl)
		if err != nil {
			log.Error("Failed to parse PURL", log.String("purl", pkg.Purl), log.Err(err))
		}
		pkgID.PURL = &pu
	}

	return pkgID
}

func ConvertFromRPCLocation(locs []*common.Location) []ftypes.Location {
	var pkgLocs []ftypes.Location
	for _, loc := range locs {
		pkgLocs = append(pkgLocs, ftypes.Location{
			StartLine: int(loc.StartLine),
			EndLine:   int(loc.EndLine),
		})
	}
	return pkgLocs
}

// ConvertToRPCVulns returns common.Vulnerability
func ConvertToRPCVulns(vulns []types.DetectedVulnerability) []*common.Vulnerability {
	var rpcVulns []*common.Vulnerability
	for _, vuln := range vulns {
		severity, err := dbTypes.NewSeverity(vuln.Severity)
		if err != nil {
			log.Warn("Severity error", log.Err(err))
		}
		cvssMap := make(map[string]*common.CVSS) // This is needed because protobuf generates a map[string]*CVSS type
		for vendor, vendorSeverity := range vuln.CVSS {
			cvssMap[string(vendor)] = &common.CVSS{
				V2Vector:  vendorSeverity.V2Vector,
				V3Vector:  vendorSeverity.V3Vector,
				V40Vector: vendorSeverity.V40Vector,
				V2Score:   vendorSeverity.V2Score,
				V3Score:   vendorSeverity.V3Score,
				V40Score:  vendorSeverity.V40Score,
			}
		}
		vendorSeverityMap := make(map[string]common.Severity)
		for vendor, vendorSeverity := range vuln.VendorSeverity {
			vendorSeverityMap[string(vendor)] = common.Severity(vendorSeverity)
		}

		var lastModifiedDate, publishedDate *timestamppb.Timestamp
		if vuln.LastModifiedDate != nil {
			lastModifiedDate = timestamppb.New(*vuln.LastModifiedDate) // nolint: errcheck
		}

		if vuln.PublishedDate != nil {
			publishedDate = timestamppb.New(*vuln.PublishedDate) // nolint: errcheck
		}

		var customAdvisoryData, customVulnData *structpb.Value
		if vuln.Custom != nil {
			customAdvisoryData, _ = structpb.NewValue(vuln.Custom) // nolint: errcheck
		}
		if vuln.Vulnerability.Custom != nil {
			customVulnData, _ = structpb.NewValue(vuln.Vulnerability.Custom) // nolint: errcheck
		}

		rpcVulns = append(rpcVulns, &common.Vulnerability{
			VulnerabilityId:    vuln.VulnerabilityID,
			VendorIds:          vuln.VendorIDs,
			PkgId:              vuln.PkgID,
			PkgName:            vuln.PkgName,
			PkgPath:            vuln.PkgPath,
			InstalledVersion:   vuln.InstalledVersion,
			FixedVersion:       vuln.FixedVersion,
			PkgIdentifier:      ConvertToRPCPkgIdentifier(vuln.PkgIdentifier),
			Status:             int32(vuln.Status),
			Title:              vuln.Title,
			Description:        vuln.Description,
			Severity:           common.Severity(severity),
			VendorSeverity:     vendorSeverityMap,
			References:         vuln.References,
			Layer:              ConvertToRPCLayer(vuln.Layer),
			Cvss:               cvssMap,
			SeveritySource:     string(vuln.SeveritySource),
			CweIds:             vuln.CweIDs,
			PrimaryUrl:         vuln.PrimaryURL,
			LastModifiedDate:   lastModifiedDate,
			PublishedDate:      publishedDate,
			CustomAdvisoryData: customAdvisoryData,
			CustomVulnData:     customVulnData,
			DataSource:         ConvertToRPCDataSource(vuln.DataSource),
		})
	}
	return rpcVulns
}

// ConvertToRPCMisconfs returns common.DetectedMisconfigurations
func ConvertToRPCMisconfs(misconfs []types.DetectedMisconfiguration) []*common.DetectedMisconfiguration {
	var rpcMisconfs []*common.DetectedMisconfiguration
	for _, m := range misconfs {
		severity, err := dbTypes.NewSeverity(m.Severity)
		if err != nil {
			log.Warn("Severity conversion error", log.Err(err))
		}

		rpcMisconfs = append(rpcMisconfs, &common.DetectedMisconfiguration{
			Type:          m.Type,
			Id:            m.ID,
			AvdId:         m.AVDID,
			Title:         m.Title,
			Description:   m.Description,
			Message:       m.Message,
			Namespace:     m.Namespace,
			Query:         m.Query,
			Resolution:    m.Resolution,
			Severity:      common.Severity(severity),
			PrimaryUrl:    m.PrimaryURL,
			References:    m.References,
			Status:        string(m.Status),
			Layer:         ConvertToRPCLayer(m.Layer),
			CauseMetadata: ConvertToRPCCauseMetadata(m.CauseMetadata),
		})
	}
	return rpcMisconfs
}

// ConvertToRPCLayer returns common.Layer
func ConvertToRPCLayer(layer ftypes.Layer) *common.Layer {
	return &common.Layer{
		Digest:    layer.Digest,
		DiffId:    layer.DiffID,
		CreatedBy: layer.CreatedBy,
	}
}

func ConvertToRPCPolicyMetadata(policy ftypes.PolicyMetadata) *common.PolicyMetadata {
	return &common.PolicyMetadata{
		Id:                 policy.ID,
		AdvId:              policy.AVDID,
		Type:               policy.Type,
		Title:              policy.Title,
		Description:        policy.Description,
		Severity:           policy.Severity,
		RecommendedActions: policy.RecommendedActions,
		References:         policy.References,
	}
}

func ConvertToRPCCauseMetadata(cause ftypes.CauseMetadata) *common.CauseMetadata {
	return &common.CauseMetadata{
		Resource:  cause.Resource,
		Provider:  cause.Provider,
		Service:   cause.Service,
		StartLine: int32(cause.StartLine),
		EndLine:   int32(cause.EndLine),
		Code:      ConvertToRPCCode(cause.Code),
		RenderedCause: &common.RenderedCause{
			Raw:         cause.RenderedCause.Raw,
			Highlighted: cause.RenderedCause.Highlighted,
		},
	}
}

// ConvertToRPCDataSource returns common.DataSource
func ConvertToRPCDataSource(ds *dbTypes.DataSource) *common.DataSource {
	if ds == nil {
		return nil
	}
	return &common.DataSource{
		Id:   string(ds.ID),
		Name: ds.Name,
		Url:  ds.URL,
	}
}

// ConvertFromRPCResults converts scanner.Result to types.Result
func ConvertFromRPCResults(rpcResults []*scanner.Result) []types.Result {
	var results []types.Result
	for _, result := range rpcResults {
		results = append(results, types.Result{
			Target:            result.Target,
			Vulnerabilities:   ConvertFromRPCVulns(result.Vulnerabilities),
			Misconfigurations: ConvertFromRPCMisconfs(result.Misconfigurations),
			Class:             types.ResultClass(result.Class),
			Type:              ftypes.TargetType(result.Type),
			Packages:          ConvertFromRPCPkgs(result.Packages),
			CustomResources:   ConvertFromRPCCustomResources(result.CustomResources),
			Secrets:           ConvertFromRPCDetectedSecrets(result.Secrets),
			Licenses:          ConvertFromRPCDetectedLicenses(result.Licenses),
		})
	}
	return results
}

func ConvertFromRPCDetectedLicenses(rpcLicenses []*common.DetectedLicense) []types.DetectedLicense {
	var licenses []types.DetectedLicense
	for _, l := range rpcLicenses {
		severity := dbTypes.Severity(l.Severity)
		licenses = append(licenses, types.DetectedLicense{
			Severity:   severity.String(),
			Category:   ConvertFromRPCLicenseCategory(l.Category),
			PkgName:    l.PkgName,
			FilePath:   l.FilePath,
			Name:       l.Name,
			Text:       l.Text,
			Confidence: float64(l.Confidence),
			Link:       l.Link,
		})
	}
	return licenses
}

func ConvertFromRPCLicenseCategory(rpcCategory common.LicenseCategory_Enum) ftypes.LicenseCategory {
	return lo.ValueOr(LicenseCategoryMap, rpcCategory, "")
}

func ConvertFromRPCLicenseType(rpcLicenseType common.LicenseType_Enum) ftypes.LicenseType {
	return lo.ValueOr(LicenseTypeMap, rpcLicenseType, "")
}

// ConvertFromRPCCustomResources converts array of cache.CustomResource to fanal.CustomResource
func ConvertFromRPCCustomResources(rpcCustomResources []*common.CustomResource) []ftypes.CustomResource {
	var resources []ftypes.CustomResource
	for _, res := range rpcCustomResources {
		resources = append(resources, ftypes.CustomResource{
			Type:     res.Type,
			FilePath: res.FilePath,
			Layer: ftypes.Layer{
				Digest: res.Layer.Digest,
				DiffID: res.Layer.DiffId,
			},
			Data: res.Data,
		})
	}
	return resources
}

func ConvertFromRPCCode(rpcCode *common.Code) ftypes.Code {
	var lines []ftypes.Line
	for _, line := range rpcCode.Lines {
		lines = append(lines, ftypes.Line{
			Number:      int(line.Number),
			Content:     line.Content,
			IsCause:     line.IsCause,
			Annotation:  line.Annotation,
			Truncated:   line.Truncated,
			Highlighted: line.Highlighted,
			FirstCause:  line.FirstCause,
			LastCause:   line.LastCause,
		})
	}
	return ftypes.Code{
		Lines: lines,
	}
}

func ConvertFromRPCDetectedSecrets(rpcFindings []*common.SecretFinding) []types.DetectedSecret {
	if len(rpcFindings) == 0 {
		return nil
	}
	return lo.Map(ConvertFromRPCSecretFindings(rpcFindings), func(s ftypes.SecretFinding, _ int) types.DetectedSecret {
		return types.DetectedSecret(s)
	})
}

func ConvertFromRPCSecretFindings(rpcFindings []*common.SecretFinding) []ftypes.SecretFinding {
	var findings []ftypes.SecretFinding
	for _, finding := range rpcFindings {
		findings = append(findings, ftypes.SecretFinding{
			RuleID:    finding.RuleId,
			Category:  ftypes.SecretRuleCategory(finding.Category),
			Severity:  finding.Severity,
			Title:     finding.Title,
			StartLine: int(finding.StartLine),
			EndLine:   int(finding.EndLine),
			Code:      ConvertFromRPCCode(finding.Code),
			Match:     finding.Match,
			Layer: ftypes.Layer{
				Digest:    finding.Layer.Digest,
				DiffID:    finding.Layer.DiffId,
				CreatedBy: finding.Layer.CreatedBy,
			},
		})
	}
	return findings
}

func ConvertFromRPCSecrets(recSecrets []*common.Secret) []ftypes.Secret {
	var secrets []ftypes.Secret
	for _, recSecret := range recSecrets {
		secrets = append(secrets, *ConvertFromRPCSecret(recSecret))
	}
	return secrets
}

func ConvertFromRPCLicenseFiles(rpcLicenses []*common.LicenseFile) []ftypes.LicenseFile {
	var licenses []ftypes.LicenseFile

	for _, lic := range rpcLicenses {
		licenses = append(licenses, ftypes.LicenseFile{
			Type:     ConvertFromRPCLicenseType(lic.LicenseType),
			FilePath: lic.FilePath,
			PkgName:  lic.PkgName,
			Findings: ConvertFromRPCLicenseFindings(lic.Fingings),
			Layer:    ConvertFromRPCLayer(lic.Layer),
		})
	}

	return licenses
}

func ConvertFromRPCLicenseFindings(rpcFindings []*common.LicenseFinding) ftypes.LicenseFindings {
	var findings ftypes.LicenseFindings

	for _, finding := range rpcFindings {
		findings = append(findings, ftypes.LicenseFinding{
			Category:   ConvertFromRPCLicenseCategory(finding.Category),
			Name:       finding.Name,
			Confidence: float64(finding.Confidence),
			Link:       finding.Link,
		})
	}

	return findings
}

// ConvertFromRPCVulns converts []*common.Vulnerability to []types.DetectedVulnerability
func ConvertFromRPCVulns(rpcVulns []*common.Vulnerability) []types.DetectedVulnerability {
	var vulns []types.DetectedVulnerability
	for _, vuln := range rpcVulns {
		severity := dbTypes.Severity(vuln.Severity)
		cvssMap := make(dbTypes.VendorCVSS) // This is needed because protobuf generates a map[string]*CVSS type
		for vendor, vendorSeverity := range vuln.Cvss {
			cvssMap[dbTypes.SourceID(vendor)] = dbTypes.CVSS{
				V2Vector:  vendorSeverity.V2Vector,
				V3Vector:  vendorSeverity.V3Vector,
				V40Vector: vendorSeverity.V40Vector,
				V2Score:   vendorSeverity.V2Score,
				V3Score:   vendorSeverity.V3Score,
				V40Score:  vendorSeverity.V40Score,
			}
		}
		vendorSeverityMap := make(dbTypes.VendorSeverity)
		for vendor, vendorSeverity := range vuln.VendorSeverity {
			vendorSeverityMap[dbTypes.SourceID(vendor)] = dbTypes.Severity(vendorSeverity)
		}

		var lastModifiedDate, publishedDate *time.Time
		if vuln.LastModifiedDate != nil {
			lastModifiedDate = lo.ToPtr(vuln.LastModifiedDate.AsTime())
		}
		if vuln.PublishedDate != nil {
			publishedDate = lo.ToPtr(vuln.PublishedDate.AsTime())
		}

		vulns = append(vulns, types.DetectedVulnerability{
			VulnerabilityID:  vuln.VulnerabilityId,
			VendorIDs:        vuln.VendorIds,
			PkgID:            vuln.PkgId,
			PkgName:          vuln.PkgName,
			PkgPath:          vuln.PkgPath,
			InstalledVersion: vuln.InstalledVersion,
			FixedVersion:     vuln.FixedVersion,
			PkgIdentifier:    ConvertFromRPCPkgIdentifier(vuln.PkgIdentifier),
			Status:           dbTypes.Status(vuln.Status),
			Vulnerability: dbTypes.Vulnerability{
				Title:            vuln.Title,
				Description:      vuln.Description,
				Severity:         severity.String(),
				CVSS:             cvssMap,
				References:       vuln.References,
				CweIDs:           vuln.CweIds,
				LastModifiedDate: lastModifiedDate,
				PublishedDate:    publishedDate,
				Custom:           vuln.CustomVulnData.AsInterface(),
				VendorSeverity:   vendorSeverityMap,
			},
			Layer:          ConvertFromRPCLayer(vuln.Layer),
			SeveritySource: dbTypes.SourceID(vuln.SeveritySource),
			PrimaryURL:     vuln.PrimaryUrl,
			Custom:         vuln.CustomAdvisoryData.AsInterface(),
			DataSource:     ConvertFromRPCDataSource(vuln.DataSource),
		})
	}
	return vulns
}

// ConvertFromRPCMisconfs converts []*common.DetectedMisconfigurations to []types.DetectedMisconfiguration
func ConvertFromRPCMisconfs(rpcMisconfs []*common.DetectedMisconfiguration) []types.DetectedMisconfiguration {
	var misconfs []types.DetectedMisconfiguration
	for _, rpcMisconf := range rpcMisconfs {
		misconfs = append(misconfs, types.DetectedMisconfiguration{
			Type:          rpcMisconf.Type,
			ID:            rpcMisconf.Id,
			AVDID:         rpcMisconf.AvdId,
			Title:         rpcMisconf.Title,
			Description:   rpcMisconf.Description,
			Message:       rpcMisconf.Message,
			Namespace:     rpcMisconf.Namespace,
			Query:         rpcMisconf.Query,
			Resolution:    rpcMisconf.Resolution,
			Severity:      rpcMisconf.Severity.String(),
			PrimaryURL:    rpcMisconf.PrimaryUrl,
			References:    rpcMisconf.References,
			Status:        types.MisconfStatus(rpcMisconf.Status),
			Layer:         ConvertFromRPCLayer(rpcMisconf.Layer),
			CauseMetadata: ConvertFromRPCCauseMetadata(rpcMisconf.CauseMetadata),
		})
	}
	return misconfs
}

// ConvertFromRPCLayer converts *common.Layer to fanal.Layer
func ConvertFromRPCLayer(rpcLayer *common.Layer) ftypes.Layer {
	if rpcLayer == nil {
		return ftypes.Layer{}
	}
	return ftypes.Layer{
		Digest:    rpcLayer.Digest,
		DiffID:    rpcLayer.DiffId,
		CreatedBy: rpcLayer.CreatedBy,
	}
}

func ConvertFromRPCPolicyMetadata(rpcPolicy *common.PolicyMetadata) ftypes.PolicyMetadata {
	if rpcPolicy == nil {
		return ftypes.PolicyMetadata{}
	}

	return ftypes.PolicyMetadata{
		ID:                 rpcPolicy.Id,
		AVDID:              rpcPolicy.AdvId,
		Type:               rpcPolicy.Type,
		Title:              rpcPolicy.Title,
		Description:        rpcPolicy.Description,
		Severity:           rpcPolicy.Severity,
		RecommendedActions: rpcPolicy.RecommendedActions,
		References:         rpcPolicy.References,
	}
}

func ConvertFromRPCCauseMetadata(rpcCause *common.CauseMetadata) ftypes.CauseMetadata {
	if rpcCause == nil {
		return ftypes.CauseMetadata{}
	}
	return ftypes.CauseMetadata{
		Resource:      rpcCause.Resource,
		Provider:      rpcCause.Provider,
		Service:       rpcCause.Service,
		StartLine:     int(rpcCause.StartLine),
		EndLine:       int(rpcCause.EndLine),
		Code:          ConvertFromRPCCode(rpcCause.Code),
		RenderedCause: ConvertFromRPCRenderedCause(rpcCause.RenderedCause),
	}
}

func ConvertFromRPCRenderedCause(rendered *common.RenderedCause) ftypes.RenderedCause {
	if rendered == nil {
		return ftypes.RenderedCause{}
	}
	return ftypes.RenderedCause{
		Raw:         rendered.Raw,
		Highlighted: rendered.Highlighted,
	}
}

// ConvertFromRPCOS converts common.OS to fanal.OS
func ConvertFromRPCOS(rpcOS *common.OS) ftypes.OS {
	if rpcOS == nil {
		return ftypes.OS{}
	}
	return ftypes.OS{
		Family:   ftypes.OSType(rpcOS.Family),
		Name:     rpcOS.Name,
		Eosl:     rpcOS.Eosl,
		Extended: rpcOS.Extended,
	}
}

// ConvertFromRPCRepository converts common.Repository to fanal.Repository
func ConvertFromRPCRepository(rpcRepo *common.Repository) *ftypes.Repository {
	if rpcRepo == nil {
		return nil
	}
	return &ftypes.Repository{
		Family:  ftypes.OSType(rpcRepo.Family),
		Release: rpcRepo.Release,
	}
}

// ConvertFromRPCDataSource converts *common.DataSource to *dbTypes.DataSource
func ConvertFromRPCDataSource(ds *common.DataSource) *dbTypes.DataSource {
	if ds == nil {
		return nil
	}
	return &dbTypes.DataSource{
		ID:   dbTypes.SourceID(ds.Id),
		Name: ds.Name,
		URL:  ds.Url,
	}
}

// ConvertFromRPCPackageInfos converts common.PackageInfo to fanal.PackageInfo
func ConvertFromRPCPackageInfos(rpcPkgInfos []*common.PackageInfo) []ftypes.PackageInfo {
	var pkgInfos []ftypes.PackageInfo
	for _, rpcPkgInfo := range rpcPkgInfos {
		pkgInfos = append(pkgInfos, ftypes.PackageInfo{
			FilePath: rpcPkgInfo.FilePath,
			Packages: ConvertFromRPCPkgs(rpcPkgInfo.Packages),
		})
	}
	return pkgInfos
}

// ConvertFromRPCApplications converts common.Application to fanal.Application
func ConvertFromRPCApplications(rpcApps []*common.Application) []ftypes.Application {
	var apps []ftypes.Application
	for _, rpcApp := range rpcApps {
		apps = append(apps, ftypes.Application{
			Type:     ftypes.LangType(rpcApp.Type),
			FilePath: rpcApp.FilePath,
			Packages: ConvertFromRPCPkgs(rpcApp.Packages),
		})
	}
	return apps
}

// ConvertFromRPCMisconfigurations converts common.Misconfiguration to fanal.Misconfiguration
func ConvertFromRPCMisconfigurations(rpcMisconfs []*common.Misconfiguration) []ftypes.Misconfiguration {
	var misconfs []ftypes.Misconfiguration
	for _, rpcMisconf := range rpcMisconfs {
		misconfs = append(misconfs, ftypes.Misconfiguration{
			FileType:  ftypes.ConfigType(rpcMisconf.FileType),
			FilePath:  rpcMisconf.FilePath,
			Successes: ConvertFromRPCMisconfResults(rpcMisconf.Successes),
			Warnings:  ConvertFromRPCMisconfResults(rpcMisconf.Warnings),
			Failures:  ConvertFromRPCMisconfResults(rpcMisconf.Failures),
			Layer:     ftypes.Layer{},
		})
	}
	return misconfs
}

// ConvertFromRPCMisconfResults converts common.MisconfResult to fanal.MisconfResult
func ConvertFromRPCMisconfResults(rpcResults []*common.MisconfResult) []ftypes.MisconfResult {
	var results []ftypes.MisconfResult
	for _, r := range rpcResults {
		results = append(results, ftypes.MisconfResult{
			Namespace:      r.Namespace,
			Message:        r.Message,
			PolicyMetadata: ConvertFromRPCPolicyMetadata(r.PolicyMetadata),
			CauseMetadata:  ConvertFromRPCCauseMetadata(r.CauseMetadata),
		})
	}
	return results
}

// ConvertFromRPCPutArtifactRequest converts cache.PutArtifactRequest to fanal.PutArtifactRequest
func ConvertFromRPCPutArtifactRequest(req *cache.PutArtifactRequest) ftypes.ArtifactInfo {
	return ftypes.ArtifactInfo{
		SchemaVersion:   int(req.ArtifactInfo.SchemaVersion),
		Architecture:    req.ArtifactInfo.Architecture,
		Created:         req.ArtifactInfo.Created.AsTime(),
		DockerVersion:   req.ArtifactInfo.DockerVersion,
		OS:              req.ArtifactInfo.Os,
		HistoryPackages: ConvertFromRPCPkgs(req.ArtifactInfo.HistoryPackages),
		Secret:          ConvertFromRPCSecret(req.ArtifactInfo.Secret),
	}
}

// ConvertFromRPCPutBlobRequest returns ftypes.BlobInfo
func ConvertFromRPCPutBlobRequest(req *cache.PutBlobRequest) ftypes.BlobInfo {
	return ftypes.BlobInfo{
		SchemaVersion:     int(req.BlobInfo.SchemaVersion),
		Digest:            req.BlobInfo.Digest,
		DiffID:            req.BlobInfo.DiffId,
		OS:                ConvertFromRPCOS(req.BlobInfo.Os),
		Repository:        ConvertFromRPCRepository(req.BlobInfo.Repository),
		PackageInfos:      ConvertFromRPCPackageInfos(req.BlobInfo.PackageInfos),
		Applications:      ConvertFromRPCApplications(req.BlobInfo.Applications),
		Misconfigurations: ConvertFromRPCMisconfigurations(req.BlobInfo.Misconfigurations),
		OpaqueDirs:        req.BlobInfo.OpaqueDirs,
		WhiteoutFiles:     req.BlobInfo.WhiteoutFiles,
		CustomResources:   ConvertFromRPCCustomResources(req.BlobInfo.CustomResources),
		Secrets:           ConvertFromRPCSecrets(req.BlobInfo.Secrets),
		Licenses:          ConvertFromRPCLicenseFiles(req.BlobInfo.Licenses),
	}
}

// ConvertToRPCOS returns common.OS
func ConvertToRPCOS(fos ftypes.OS) *common.OS {
	return &common.OS{
		Family:   string(fos.Family),
		Name:     fos.Name,
		Eosl:     fos.Eosl,
		Extended: fos.Extended,
	}
}

// ConvertToRPCRepository returns common.Repository
func ConvertToRPCRepository(repo *ftypes.Repository) *common.Repository {
	if repo == nil {
		return nil
	}
	return &common.Repository{
		Family:  string(repo.Family),
		Release: repo.Release,
	}
}

// ConvertToRPCArtifactInfo returns PutArtifactRequest
func ConvertToRPCArtifactInfo(imageID string, imageInfo ftypes.ArtifactInfo) *cache.PutArtifactRequest {

	t := timestamppb.New(imageInfo.Created)
	if err := t.CheckValid(); err != nil {
		log.Warn("Invalid timestamp", log.Err(err))
	}

	return &cache.PutArtifactRequest{
		ArtifactId: imageID,
		ArtifactInfo: &cache.ArtifactInfo{
			SchemaVersion:   int32(imageInfo.SchemaVersion),
			Architecture:    imageInfo.Architecture,
			Created:         t,
			DockerVersion:   imageInfo.DockerVersion,
			Os:              imageInfo.OS,
			HistoryPackages: ConvertToRPCPkgs(imageInfo.HistoryPackages),
			Secret:          ConvertToRPCSecret(imageInfo.Secret),
		},
	}
}

// ConvertToRPCPutBlobRequest returns PutBlobRequest
func ConvertToRPCPutBlobRequest(diffID string, blobInfo ftypes.BlobInfo) *cache.PutBlobRequest {
	var packageInfos []*common.PackageInfo
	for _, pkgInfo := range blobInfo.PackageInfos {
		packageInfos = append(packageInfos, &common.PackageInfo{
			FilePath: pkgInfo.FilePath,
			Packages: ConvertToRPCPkgs(pkgInfo.Packages),
		})
	}

	var applications []*common.Application
	for _, app := range blobInfo.Applications {
		applications = append(applications, &common.Application{
			Type:     string(app.Type),
			FilePath: app.FilePath,
			Packages: ConvertToRPCPkgs(app.Packages),
		})
	}

	var misconfigurations []*common.Misconfiguration
	for _, m := range blobInfo.Misconfigurations {
		misconfigurations = append(misconfigurations, &common.Misconfiguration{
			FileType:  string(m.FileType),
			FilePath:  m.FilePath,
			Successes: ConvertToMisconfResults(m.Successes),
			Warnings:  ConvertToMisconfResults(m.Warnings),
			Failures:  ConvertToMisconfResults(m.Failures),
		})

	}

	var customResources []*common.CustomResource
	for _, res := range blobInfo.CustomResources {
		data, err := structpb.NewValue(res.Data)
		if err != nil {

		} else {
			customResources = append(customResources, &common.CustomResource{
				Type:     res.Type,
				FilePath: res.FilePath,
				Layer: &common.Layer{
					Digest: res.Layer.Digest,
					DiffId: res.Layer.DiffID,
				},
				Data: data,
			})
		}
	}

	return &cache.PutBlobRequest{
		DiffId: diffID,
		BlobInfo: &cache.BlobInfo{
			SchemaVersion:     ftypes.BlobJSONSchemaVersion,
			Digest:            blobInfo.Digest,
			DiffId:            blobInfo.DiffID,
			Os:                ConvertToRPCOS(blobInfo.OS),
			Repository:        ConvertToRPCRepository(blobInfo.Repository),
			PackageInfos:      packageInfos,
			Applications:      applications,
			Misconfigurations: misconfigurations,
			OpaqueDirs:        blobInfo.OpaqueDirs,
			WhiteoutFiles:     blobInfo.WhiteoutFiles,
			CustomResources:   customResources,
			Secrets:           ConvertToRPCSecrets(blobInfo.Secrets),
			Licenses:          ConvertToRPCLicenseFiles(blobInfo.Licenses),
		},
	}
}

// ConvertToMisconfResults returns common.MisconfResult
func ConvertToMisconfResults(results []ftypes.MisconfResult) []*common.MisconfResult {
	var rpcResults []*common.MisconfResult
	for _, r := range results {
		rpcResults = append(rpcResults, &common.MisconfResult{
			Namespace:      r.Namespace,
			Message:        r.Message,
			PolicyMetadata: ConvertToRPCPolicyMetadata(r.PolicyMetadata),
			CauseMetadata:  ConvertToRPCCauseMetadata(r.CauseMetadata),
		})
	}
	return rpcResults
}

// ConvertToMissingBlobsRequest returns MissingBlobsRequest object
func ConvertToMissingBlobsRequest(imageID string, layerIDs []string) *cache.MissingBlobsRequest {
	return &cache.MissingBlobsRequest{
		ArtifactId: imageID,
		BlobIds:    layerIDs,
	}
}

// ConvertToRPCScanResponse converts types.Result to ScanResponse
func ConvertToRPCScanResponse(results types.Results, fos ftypes.OS) *scanner.ScanResponse {
	var rpcResults []*scanner.Result
	for _, result := range results {
		secretFindings := lo.Map(result.Secrets, func(s types.DetectedSecret, _ int) ftypes.SecretFinding {
			return ftypes.SecretFinding(s)
		})
		rpcResults = append(rpcResults, &scanner.Result{
			Target:            result.Target,
			Class:             string(result.Class),
			Type:              string(result.Type),
			Packages:          ConvertToRPCPkgs(result.Packages),
			Vulnerabilities:   ConvertToRPCVulns(result.Vulnerabilities),
			Misconfigurations: ConvertToRPCMisconfs(result.Misconfigurations),
			Secrets:           ConvertToRPCSecretFindings(secretFindings),
			Licenses:          ConvertToRPCLicenses(result.Licenses),
			CustomResources:   ConvertToRPCCustomResources(result.CustomResources),
		})
	}

	return &scanner.ScanResponse{
		Os:      ConvertToRPCOS(fos),
		Results: rpcResults,
	}
}

func ConvertToRPCLicenses(licenses []types.DetectedLicense) []*common.DetectedLicense {
	var rpcLicenses []*common.DetectedLicense
	for _, l := range licenses {
		severity, err := dbTypes.NewSeverity(l.Severity)
		if err != nil {
			log.Warn("Severity conversion error", log.Err(err))
		}
		rpcLicenses = append(rpcLicenses, &common.DetectedLicense{
			Severity:   common.Severity(severity),
			Category:   ConvertToRPCLicenseCategory(l.Category),
			PkgName:    l.PkgName,
			FilePath:   l.FilePath,
			Name:       l.Name,
			Text:       l.Text,
			Confidence: float32(l.Confidence),
			Link:       l.Link,
		})
	}

	return rpcLicenses
}

func ConvertToRPCLicenseCategory(category ftypes.LicenseCategory) common.LicenseCategory_Enum {
	return ByValueOr(LicenseCategoryMap, category, common.LicenseCategory_UNSPECIFIED)
}

func ConvertToRPCLicenseType(ty ftypes.LicenseType) common.LicenseType_Enum {
	return ByValueOr(LicenseTypeMap, ty, common.LicenseType_UNSPECIFIED)
}

func ConvertToDeleteBlobsRequest(blobIDs []string) *cache.DeleteBlobsRequest {
	return &cache.DeleteBlobsRequest{BlobIds: blobIDs}
}

func ConvertFromDeleteBlobsRequest(deleteBlobsRequest *cache.DeleteBlobsRequest) []string {
	if deleteBlobsRequest == nil {
		return []string{}
	}
	return deleteBlobsRequest.GetBlobIds()
}

// ConvertFromRPCSecret converts common.Secret to fanal.Secret
func ConvertFromRPCSecret(rpcSecret *common.Secret) *ftypes.Secret {
	if rpcSecret == nil {
		return nil
	}
	return &ftypes.Secret{
		FilePath: rpcSecret.Filepath,
		Findings: ConvertFromRPCSecretFindings(rpcSecret.Findings),
	}
}

// ConvertToRPCSecret converts fanal.Secret to common.Secret
func ConvertToRPCSecret(secret *ftypes.Secret) *common.Secret {
	if secret == nil {
		return nil
	}
	return &common.Secret{
		Filepath: secret.FilePath,
		Findings: ConvertToRPCSecretFindings(secret.Findings),
	}
}
