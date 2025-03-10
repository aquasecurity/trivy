package report

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"

	containerName "github.com/google/go-containerregistry/pkg/name"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	sarifOsPackageVulnerability        = "OsPackageVulnerability"
	sarifLanguageSpecificVulnerability = "LanguageSpecificPackageVulnerability"
	sarifConfigFiles                   = "Misconfiguration"
	sarifSecretFiles                   = "Secret"
	sarifLicenseFiles                  = "License"
	sarifUnknownIssue                  = "UnknownIssue"

	sarifError   = "error"
	sarifWarning = "warning"
	sarifNote    = "note"
	sarifNone    = "none"

	columnKind = "utf16CodeUnits"

	builtinRulesUrl = "https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/secret/builtin-rules.go" // list all secrets
)

var (
	rootPath = "file:///"

	// pathRegex to extract file path in case string includes (distro:version)
	pathRegex = regexp.MustCompile(`(?P<path>.+?)(?:\s*\((?:.*?)\).*?)?$`)
)

// SarifWriter implements result Writer
type SarifWriter struct {
	Output        io.Writer
	Version       string
	run           *sarif.Run
	locationCache map[string][]location
	Target        string
}

type sarifData struct {
	title            string
	vulnerabilityId  string
	shortDescription string
	fullDescription  string
	helpText         string
	helpMarkdown     string
	resourceClass    types.ResultClass
	severity         string
	url              *url.URL
	resultIndex      int
	artifactLocation *url.URL
	locationMessage  string
	message          string
	cvssScore        string
	locations        []location
}

type location struct {
	startLine int
	endLine   int
}

func (sw *SarifWriter) addSarifRule(data *sarifData) {
	r := sw.run.AddRule(data.vulnerabilityId).
		WithName(toSarifRuleName(data.resourceClass)).
		WithDescription(data.vulnerabilityId).
		WithShortDescription(&sarif.MultiformatMessageString{Text: &data.shortDescription}).
		WithFullDescription(&sarif.MultiformatMessageString{Text: &data.fullDescription}).
		WithHelp(&sarif.MultiformatMessageString{
			Text:     &data.helpText,
			Markdown: &data.helpMarkdown,
		}).
		WithDefaultConfiguration(&sarif.ReportingConfiguration{
			Level: toSarifErrorLevel(data.severity),
		}).
		WithProperties(sarif.Properties{
			"tags": []string{
				data.title,
				"security",
				data.severity,
			},
			"precision":         "very-high",
			"security-severity": data.cvssScore,
		})
	if data.url != nil && data.url.String() != "" {
		r.WithHelpURI(data.url.String())
	}
}

func (sw *SarifWriter) addSarifResult(data *sarifData) {
	sw.addSarifRule(data)

	result := sarif.NewRuleResult(data.vulnerabilityId).
		WithRuleIndex(data.resultIndex).
		WithMessage(sarif.NewTextMessage(data.message)).
		WithLevel(toSarifErrorLevel(data.severity)).
		WithLocations(toSarifLocations(data.locations, data.artifactLocation.String(), data.locationMessage))
	sw.run.AddResult(result)
}

func getRuleIndex(id string, indexes map[string]int) int {
	if i, ok := indexes[id]; ok {
		return i
	} else {
		l := len(indexes)
		indexes[id] = l
		return l
	}
}

func (sw *SarifWriter) Write(ctx context.Context, report types.Report) error {
	sarifReport, err := sarif.New(sarif.Version210)
	if err != nil {
		return xerrors.Errorf("error creating a new sarif template: %w", err)
	}
	sw.run = sarif.NewRunWithInformationURI("Trivy", "https://github.com/aquasecurity/trivy")
	sw.run.Tool.Driver.WithVersion(sw.Version)
	sw.run.Tool.Driver.WithFullName("Trivy Vulnerability Scanner")
	sw.locationCache = make(map[string][]location)
	if report.ArtifactType == ftypes.TypeContainerImage {
		sw.run.Properties = sarif.Properties{
			"imageName":   report.ArtifactName,
			"repoTags":    report.Metadata.RepoTags,
			"repoDigests": report.Metadata.RepoDigests,
			"imageID":     report.Metadata.ImageID,
		}
	}
	if sw.Target != "" {
		absPath, _ := filepath.Abs(sw.Target)
		rootPath = fmt.Sprintf("file://%s/", absPath)
	}

	ruleIndexes := make(map[string]int)
	for _, res := range report.Results {
		target := ToPathUri(res.Target, res.Class)

		for _, vuln := range res.Vulnerabilities {
			fullDescription := vuln.Description
			if fullDescription == "" {
				fullDescription = vuln.Title
			}
			path := target
			if vuln.PkgPath != "" {
				path = ToPathUri(vuln.PkgPath, res.Class)
			}
			sw.addSarifResult(&sarifData{
				title:            "vulnerability",
				vulnerabilityId:  vuln.VulnerabilityID,
				severity:         vuln.Severity,
				cvssScore:        getCVSSScore(vuln),
				url:              toUri(vuln.PrimaryURL),
				resourceClass:    res.Class,
				artifactLocation: toUri(path),
				locationMessage:  fmt.Sprintf("%v: %v@%v", path, vuln.PkgName, vuln.InstalledVersion),
				locations:        sw.getLocations(vuln.PkgName, vuln.InstalledVersion, path, res.Packages),
				resultIndex:      getRuleIndex(vuln.VulnerabilityID, ruleIndexes),
				shortDescription: vuln.Title,
				fullDescription:  fullDescription,
				helpText: fmt.Sprintf("Vulnerability %v\nSeverity: %v\nPackage: %v\nFixed Version: %v\nLink: [%v](%v)\n%v",
					vuln.VulnerabilityID, vuln.Severity, vuln.PkgName, vuln.FixedVersion, vuln.VulnerabilityID, vuln.PrimaryURL, vuln.Description),
				helpMarkdown: fmt.Sprintf("**Vulnerability %v**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|%v|%v|%v|[%v](%v)|\n\n%v",
					vuln.VulnerabilityID, vuln.Severity, vuln.PkgName, vuln.FixedVersion, vuln.VulnerabilityID, vuln.PrimaryURL, vuln.Description),
				message: fmt.Sprintf("Package: %v\nInstalled Version: %v\nVulnerability %v\nSeverity: %v\nFixed Version: %v\nLink: [%v](%v)",
					vuln.PkgName, vuln.InstalledVersion, vuln.VulnerabilityID, vuln.Severity, vuln.FixedVersion, vuln.VulnerabilityID, vuln.PrimaryURL),
			})
		}
		for _, misconf := range res.Misconfigurations {
			locationURI := clearURI(res.Target)
			sw.addSarifResult(&sarifData{
				title:            "misconfiguration",
				vulnerabilityId:  misconf.ID,
				severity:         misconf.Severity,
				cvssScore:        severityToScore(misconf.Severity),
				url:              toUri(misconf.PrimaryURL),
				resourceClass:    res.Class,
				artifactLocation: toUri(locationURI),
				locationMessage:  locationURI,
				locations: []location{
					{
						startLine: misconf.CauseMetadata.StartLine,
						endLine:   misconf.CauseMetadata.EndLine,
					},
				},
				resultIndex:      getRuleIndex(misconf.ID, ruleIndexes),
				shortDescription: misconf.Title,
				fullDescription:  misconf.Description,
				helpText: fmt.Sprintf("Misconfiguration %v\nType: %s\nSeverity: %v\nCheck: %v\nMessage: %v\nLink: [%v](%v)\n%s",
					misconf.ID, misconf.Type, misconf.Severity, misconf.Title, misconf.Message, misconf.ID, misconf.PrimaryURL, misconf.Description),
				helpMarkdown: fmt.Sprintf("**Misconfiguration %v**\n| Type | Severity | Check | Message | Link |\n| --- | --- | --- | --- | --- |\n|%v|%v|%v|%s|[%v](%v)|\n\n%v",
					misconf.ID, misconf.Type, misconf.Severity, misconf.Title, misconf.Message, misconf.ID, misconf.PrimaryURL, misconf.Description),
				message: fmt.Sprintf("Artifact: %v\nType: %v\nVulnerability %v\nSeverity: %v\nMessage: %v\nLink: [%v](%v)",
					locationURI, res.Type, misconf.ID, misconf.Severity, misconf.Message, misconf.ID, misconf.PrimaryURL),
			})
		}
		for _, secret := range res.Secrets {
			sw.addSarifResult(&sarifData{
				title:            "secret",
				vulnerabilityId:  secret.RuleID,
				severity:         secret.Severity,
				cvssScore:        severityToScore(secret.Severity),
				url:              toUri(builtinRulesUrl),
				resourceClass:    res.Class,
				artifactLocation: toUri(target),
				locationMessage:  target,
				locations: []location{
					{
						startLine: secret.StartLine,
						endLine:   secret.EndLine,
					},
				},
				resultIndex:      getRuleIndex(secret.RuleID, ruleIndexes),
				shortDescription: secret.Title,
				fullDescription:  secret.Match,
				helpText: fmt.Sprintf("Secret %v\nSeverity: %v\nMatch: %s",
					secret.Title, secret.Severity, secret.Match),
				helpMarkdown: fmt.Sprintf("**Secret %v**\n| Severity | Match |\n| --- | --- |\n|%v|%v|",
					secret.Title, secret.Severity, secret.Match),
				message: fmt.Sprintf("Artifact: %v\nType: %v\nSecret %v\nSeverity: %v\nMatch: %v",
					res.Target, res.Type, secret.Title, secret.Severity, secret.Match),
			})
		}
		for _, license := range res.Licenses {
			id := fmt.Sprintf("%s:%s", license.PkgName, license.Name)
			desc := fmt.Sprintf("%s in %s", license.Name, license.PkgName)
			sw.addSarifResult(&sarifData{
				title:            "license",
				vulnerabilityId:  id,
				severity:         license.Severity,
				cvssScore:        severityToScore(license.Severity),
				url:              toUri(license.Link),
				resourceClass:    res.Class,
				artifactLocation: toUri(target),
				resultIndex:      getRuleIndex(id, ruleIndexes),
				shortDescription: desc,
				fullDescription:  desc,
				helpText: fmt.Sprintf("License %s\nClassification: %s\nPkgName: %s\nPath: %s",
					license.Name, license.Category, license.PkgName, license.FilePath),
				helpMarkdown: fmt.Sprintf("**License %s**\n| PkgName | Classification | Path |\n| --- | --- | --- |\n|%s|%s|%s|",
					license.Name, license.PkgName, license.Category, license.FilePath),
				message: fmt.Sprintf("Artifact: %s\nLicense %s\nPkgName: %s\n Classification: %s\n Path: %s",
					res.Target, license.Name, license.Category, license.PkgName, license.FilePath),
			})
		}

	}
	sw.run.ColumnKind = columnKind
	sw.run.OriginalUriBaseIDs = map[string]*sarif.ArtifactLocation{
		"ROOTPATH": {URI: &rootPath},
	}
	sarifReport.AddRun(sw.run)
	return sarifReport.PrettyWrite(sw.Output)
}

func toSarifLocations(locations []location, artifactLocation, locationMessage string) []*sarif.Location {
	var sarifLocs []*sarif.Location
	// add default (hardcoded) location for vulnerabilities that don't support locations
	if len(locations) == 0 {
		locations = append(locations, location{
			startLine: 1,
			endLine:   1,
		})
	}

	// some dependencies can be placed in multiple places.
	// e.g.https://github.com/aquasecurity/go-dep-parser/pull/134#discussion_r985353240
	// create locations for each place.

	for _, l := range locations {
		// location is missed. Use default (hardcoded) value (misconfigurations have this case)
		if l.startLine == 0 && l.endLine == 0 {
			l.startLine = 1
			l.endLine = 1
		}
		region := sarif.NewRegion().WithStartLine(l.startLine).WithEndLine(l.endLine).WithStartColumn(1).WithEndColumn(1)
		loc := sarif.NewPhysicalLocation().
			WithArtifactLocation(sarif.NewSimpleArtifactLocation(artifactLocation).WithUriBaseId("ROOTPATH")).
			WithRegion(region)
		sarifLocs = append(sarifLocs, sarif.NewLocation().WithMessage(sarif.NewTextMessage(locationMessage)).WithPhysicalLocation(loc))
	}

	return sarifLocs
}

func toSarifRuleName(class types.ResultClass) string {
	switch class {
	case types.ClassOSPkg:
		return sarifOsPackageVulnerability
	case types.ClassLangPkg:
		return sarifLanguageSpecificVulnerability
	case types.ClassConfig:
		return sarifConfigFiles
	case types.ClassSecret:
		return sarifSecretFiles
	case types.ClassLicense, types.ClassLicenseFile:
		return sarifLicenseFiles
	default:
		return sarifUnknownIssue
	}
}

func toSarifErrorLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return sarifError
	case "MEDIUM":
		return sarifWarning
	case "LOW", "UNKNOWN":
		return sarifNote
	default:
		return sarifNone
	}
}

func ToPathUri(input string, resultClass types.ResultClass) string {
	// we only need to convert OS input
	// e.g. image names, digests, etc...
	if resultClass != types.ClassOSPkg {
		return input
	}
	var matches = pathRegex.FindStringSubmatch(input)
	if matches != nil {
		input = matches[pathRegex.SubexpIndex("path")]
	}
	ref, err := containerName.ParseReference(input)
	if err == nil {
		input = ref.Context().RepositoryStr()
	}

	return clearURI(input)
}

// clearURI clears URI for misconfigs
func clearURI(s string) string {
	s = strings.ReplaceAll(s, "\\", "/")
	// cf. https://developer.hashicorp.com/terraform/language/modules/sources
	switch {
	case strings.HasPrefix(s, "git@github.com:"):
		// build GitHub url format
		// e.g. `git@github.com:terraform-aws-modules/terraform-aws-s3-bucket.git?ref=v4.2.0/main.tf` -> `github.com/terraform-aws-modules/terraform-aws-s3-bucket/tree/v4.2.0/main.tf`
		// cf. https://github.com/aquasecurity/trivy/issues/7897
		s = strings.ReplaceAll(s, "git@github.com:", "github.com/")
		s = strings.ReplaceAll(s, ".git", "")
		s = strings.ReplaceAll(s, "?ref=", "/tree/")
	case strings.HasPrefix(s, "git::https:/") && !strings.HasPrefix(s, "git::https://"):
		s = strings.TrimPrefix(s, "git::https:/")
		s = strings.ReplaceAll(s, ".git", "")
	case strings.HasPrefix(s, "git::ssh://"):
		// `"`git::ssh://username@example.com/storage.git` -> `example.com/storage.git`
		if _, u, ok := strings.Cut(s, "@"); ok {
			s = u
		}
		s = strings.ReplaceAll(s, ".git", "")
	case strings.HasPrefix(s, "git::"):
		// `git::https://example.com/vpc.git` -> `https://example.com/vpc`
		s = strings.TrimPrefix(s, "git::")
		s = strings.ReplaceAll(s, ".git", "")
	case strings.HasPrefix(s, "hg::"):
		// `hg::http://example.com/vpc.hg` -> `http://example.com/vpc`
		s = strings.TrimPrefix(s, "hg::")
		s = strings.ReplaceAll(s, ".hg", "")
	case strings.HasPrefix(s, "s3::"):
		// `s3::https://s3-eu-west-1.amazonaws.com/examplecorp-terraform-modules/vpc.zip` -> `https://s3-eu-west-1.amazonaws.com/examplecorp-terraform-modules/vpc.zip`
		s = strings.TrimPrefix(s, "s3::")
	case strings.HasPrefix(s, "gcs::"):
		// `gcs::https://www.googleapis.com/storage/v1/modules/foomodule.zipp` -> `https://www.googleapis.com/storage/v1/modules/foomodule.zip`
		s = strings.TrimPrefix(s, "gcs::")
	}

	return s
}

func toUri(str string) *url.URL {
	uri, err := url.Parse(str)
	if err != nil {
		logger := log.WithPrefix("sarif")
		logger.Error("Unable to parse URI", log.String("URI", str), log.Err(err))
	}
	return uri
}

func (sw *SarifWriter) getLocations(name, version, path string, pkgs []ftypes.Package) []location {
	id := fmt.Sprintf("%s@%s@%s", path, name, version)
	locs, ok := sw.locationCache[id]
	if !ok {
		for _, pkg := range pkgs {
			if name == pkg.Name && version == pkg.Version {
				for _, l := range pkg.Locations {
					loc := location{
						startLine: l.StartLine,
						endLine:   l.EndLine,
					}
					locs = append(locs, loc)
				}
				sw.locationCache[id] = locs
				return locs
			}
		}
	}
	return locs
}

func getCVSSScore(vuln types.DetectedVulnerability) string {
	// Take the vendor score
	if cvss, ok := vuln.CVSS[vuln.SeveritySource]; ok {
		return fmt.Sprintf("%.1f", cvss.V3Score)
	}

	// Converts severity to score
	return severityToScore(vuln.Severity)
}

func severityToScore(severity string) string {
	switch severity {
	case "CRITICAL":
		return "9.5"
	case "HIGH":
		return "8.0"
	case "MEDIUM":
		return "5.5"
	case "LOW":
		return "2.0"
	default:
		return "0.0"
	}
}
