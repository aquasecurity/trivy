package cyclonedx

import (
	"sort"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	dtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	Namespace = "aquasecurity:trivy:"

	PropertySchemaVersion = "SchemaVersion"
	PropertyType          = "Type"
	PropertyClass         = "Class"

	// Image properties
	PropertySize       = "Size"
	PropertyImageID    = "ImageID"
	PropertyRepoDigest = "RepoDigest"
	PropertyDiffID     = "DiffID"
	PropertyRepoTag    = "RepoTag"

	// Package properties
	PropertySrcName         = "SrcName"
	PropertySrcVersion      = "SrcVersion"
	PropertySrcRelease      = "SrcRelease"
	PropertySrcEpoch        = "SrcEpoch"
	PropertyModularitylabel = "Modularitylabel"
	PropertyFilePath        = "FilePath"
	PropertyLayerDigest     = "LayerDigest"
	PropertyLayerDiffID     = "LayerDiffID"
)

const (
	// https://json-schema.org/understanding-json-schema/reference/string.html#dates-and-times
	timeLayout = "2006-01-02T15:04:05+00:00"
)

func Vulnerability(vuln types.DetectedVulnerability, bomRef string) cdx.Vulnerability {
	v := cdx.Vulnerability{
		ID:          vuln.VulnerabilityID,
		Source:      source(vuln.DataSource),
		Ratings:     ratings(vuln),
		CWEs:        cwes(vuln.CweIDs),
		Description: vuln.Description,
		Advisories:  advisories(vuln.References),
	}
	if vuln.PublishedDate != nil {
		v.Published = vuln.PublishedDate.Format(timeLayout)
	}
	if vuln.LastModifiedDate != nil {
		v.Updated = vuln.LastModifiedDate.Format(timeLayout)
	}

	v.Affects = &[]cdx.Affects{Affects(bomRef, vuln.InstalledVersion)}

	return v
}

func Affects(ref, version string) cdx.Affects {
	return cdx.Affects{
		Ref: ref,
		Range: &[]cdx.AffectedVersions{
			{
				Version: version,
				Status:  cdx.VulnerabilityStatusAffected,
				// "AffectedVersions.Range" is not included, because it does not exist in DetectedVulnerability.
			},
		},
	}
}

func Properties(pkg ftypes.Package) []cdx.Property {
	props := []struct {
		name  string
		value string
	}{
		{PropertyFilePath, pkg.FilePath},
		{PropertySrcName, pkg.SrcName},
		{PropertySrcVersion, pkg.SrcVersion},
		{PropertySrcRelease, pkg.SrcRelease},
		{PropertySrcEpoch, strconv.Itoa(pkg.SrcEpoch)},
		{PropertyModularitylabel, pkg.Modularitylabel},
		{PropertyLayerDigest, pkg.Layer.Digest},
		{PropertyLayerDiffID, pkg.Layer.DiffID},
	}

	var properties []cdx.Property
	for _, prop := range props {
		properties = AppendProperties(properties, prop.name, prop.value)
	}

	return properties
}

func AppendProperties(properties []cdx.Property, key, value string) []cdx.Property {
	if value == "" || (key == PropertySrcEpoch && value == "0") {
		return properties
	}
	return append(properties, Property(key, value))
}

func Property(key, value string) cdx.Property {
	return cdx.Property{
		Name:  Namespace + key,
		Value: value,
	}
}

func advisories(refs []string) *[]cdx.Advisory {
	var advs []cdx.Advisory
	for _, ref := range refs {
		advs = append(advs, cdx.Advisory{
			URL: ref,
		})
	}
	return &advs
}

func cwes(cweIDs []string) *[]int {
	// to skip cdx.Vulnerability.CWEs when generating json
	// we should return 'clear' nil without 'type' interface part
	if cweIDs == nil {
		return nil
	}
	var ret []int
	for _, cweID := range cweIDs {
		number, err := strconv.Atoi(strings.TrimPrefix(strings.ToLower(cweID), "cwe-"))
		if err != nil {
			log.Logger.Debugf("cwe id parse error: %s", err)
			continue
		}
		ret = append(ret, number)
	}
	return &ret
}

func ratings(vulnerability types.DetectedVulnerability) *[]cdx.VulnerabilityRating {
	var rates []cdx.VulnerabilityRating
	for sourceID, severity := range vulnerability.VendorSeverity {
		// When the vendor also provides CVSS score/vector
		if cvss, ok := vulnerability.CVSS[sourceID]; ok {
			if cvss.V2Score != 0 || cvss.V2Vector != "" {
				rates = append(rates, ratingV2(sourceID, severity, cvss))
			}
			if cvss.V3Score != 0 || cvss.V3Vector != "" {
				rates = append(rates, ratingV3(sourceID, severity, cvss))
			}
		} else { // When the vendor provides only severity
			rate := cdx.VulnerabilityRating{
				Source: &cdx.Source{
					Name: string(sourceID),
				},
				Severity: toCDXSeverity(severity),
			}
			rates = append(rates, rate)
		}
	}

	// For consistency
	sort.Slice(rates, func(i, j int) bool {
		if rates[i].Source.Name != rates[j].Source.Name {
			return rates[i].Source.Name < rates[j].Source.Name
		}
		if rates[i].Method != rates[j].Method {
			return rates[i].Method < rates[j].Method
		}
		if rates[i].Score != nil && rates[j].Score != nil {
			return *rates[i].Score < *rates[j].Score
		}
		return rates[i].Vector < rates[j].Vector
	})
	return &rates
}

func ratingV2(sourceID dtypes.SourceID, severity dtypes.Severity, cvss dtypes.CVSS) cdx.VulnerabilityRating {
	cdxSeverity := toCDXSeverity(severity)

	// Trivy keeps only CVSSv3 severity for NVD.
	// The CVSSv2 severity must be calculated according to CVSSv2 score.
	if sourceID == vulnerability.NVD {
		cdxSeverity = nvdSeverityV2(cvss.V2Score)
	}
	return cdx.VulnerabilityRating{
		Source: &cdx.Source{
			Name: string(sourceID),
		},
		Score:    &cvss.V2Score,
		Method:   cdx.ScoringMethodCVSSv2,
		Severity: cdxSeverity,
		Vector:   cvss.V2Vector,
	}
}

func nvdSeverityV2(score float64) cdx.Severity {
	// cf. https://nvd.nist.gov/vuln-metrics/cvss
	switch {
	case score < 4.0:
		return cdx.SeverityInfo
	case 4.0 <= score && score < 7.0:
		return cdx.SeverityMedium
	case 7.0 <= score:
		return cdx.SeverityHigh
	}
	return cdx.SeverityUnknown
}

func ratingV3(sourceID dtypes.SourceID, severity dtypes.Severity, cvss dtypes.CVSS) cdx.VulnerabilityRating {
	rate := cdx.VulnerabilityRating{
		Source: &cdx.Source{
			Name: string(sourceID),
		},
		Score:    &cvss.V3Score,
		Method:   cdx.ScoringMethodCVSSv3,
		Severity: toCDXSeverity(severity),
		Vector:   cvss.V3Vector,
	}
	if strings.HasPrefix(cvss.V3Vector, "CVSS:3.1") {
		rate.Method = cdx.ScoringMethodCVSSv31
	}
	return rate
}

func toCDXSeverity(s dtypes.Severity) cdx.Severity {
	switch s {
	case dtypes.SeverityLow:
		return cdx.SeverityLow
	case dtypes.SeverityMedium:
		return cdx.SeverityMedium
	case dtypes.SeverityHigh:
		return cdx.SeverityHigh
	case dtypes.SeverityCritical:
		return cdx.SeverityCritical
	default:
		return cdx.SeverityUnknown
	}
}

func source(source *dtypes.DataSource) *cdx.Source {
	if source == nil {
		return nil
	}

	return &cdx.Source{
		Name: string(source.ID),
		URL:  source.URL,
	}
}
