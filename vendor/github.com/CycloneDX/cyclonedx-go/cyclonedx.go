// This file is part of CycloneDX Go
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an “AS IS” BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) OWASP Foundation. All Rights Reserved.

package cyclonedx

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
)

const (
	BOMFormat      = "CycloneDX"
	defaultVersion = 1
	SpecVersion    = "1.4"
	XMLNamespace   = "http://cyclonedx.org/schema/bom/1.4"
)

type Advisory struct {
	Title string `json:"title,omitempty" xml:"title,omitempty"`
	URL   string `json:"url" xml:"url"`
}

type AffectedVersions struct {
	Version string              `json:"version,omitempty" xml:"version,omitempty"`
	Range   string              `json:"range,omitempty" xml:"range,omitempty"`
	Status  VulnerabilityStatus `json:"status" xml:"status"`
}

type Affects struct {
	Ref   string              `json:"ref" xml:"ref"`
	Range *[]AffectedVersions `json:"versions,omitempty" xml:"versions>version,omitempty"`
}

type AttachedText struct {
	Content     string `json:"content" xml:",innerxml"`
	ContentType string `json:"contentType,omitempty" xml:"content-type,attr,omitempty"`
	Encoding    string `json:"encoding,omitempty" xml:"encoding,attr,omitempty"`
}

type BOM struct {
	// XML specific fields
	XMLName xml.Name `json:"-" xml:"bom"`
	XMLNS   string   `json:"-" xml:"xmlns,attr"`

	// JSON specific fields
	BOMFormat   string `json:"bomFormat" xml:"-"`
	SpecVersion string `json:"specVersion" xml:"-"`

	SerialNumber       string               `json:"serialNumber,omitempty" xml:"serialNumber,attr,omitempty"`
	Version            int                  `json:"version" xml:"version,attr"`
	Metadata           *Metadata            `json:"metadata,omitempty" xml:"metadata,omitempty"`
	Components         *[]Component         `json:"components,omitempty" xml:"components>component,omitempty"`
	Services           *[]Service           `json:"services,omitempty" xml:"services>service,omitempty"`
	ExternalReferences *[]ExternalReference `json:"externalReferences,omitempty" xml:"externalReferences>reference,omitempty"`
	Dependencies       *[]Dependency        `json:"dependencies,omitempty" xml:"dependencies>dependency,omitempty"`
	Compositions       *[]Composition       `json:"compositions,omitempty" xml:"compositions>composition,omitempty"`
	Properties         *[]Property          `json:"properties,omitempty" xml:"properties>property,omitempty"`
	Vulnerabilities    *[]Vulnerability     `json:"vulnerabilities,omitempty" xml:"vulnerabilities>vulnerability,omitempty"`
}

func NewBOM() *BOM {
	return &BOM{
		XMLNS:       XMLNamespace,
		BOMFormat:   BOMFormat,
		SpecVersion: SpecVersion,
		Version:     defaultVersion,
	}
}

type BOMFileFormat int

const (
	BOMFileFormatXML BOMFileFormat = iota
	BOMFileFormatJSON
)

// Bool is a convenience function to transform a value of the primitive type bool to a pointer of bool
func Bool(value bool) *bool {
	return &value
}

type BOMReference string

// bomReferenceXML is temporarily used for marshalling and unmarshalling BOMReference instances to and from XML
type bomReferenceXML struct {
	Ref string `json:"-" xml:"ref,attr"`
}

func (b BOMReference) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(bomReferenceXML{Ref: string(b)}, start)
}

func (b *BOMReference) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	bXML := bomReferenceXML{}
	if err := d.DecodeElement(&bXML, &start); err != nil {
		return err
	}
	*b = BOMReference(bXML.Ref)
	return nil
}

type ComponentType string

const (
	ComponentTypeApplication ComponentType = "application"
	ComponentTypeContainer   ComponentType = "container"
	ComponentTypeDevice      ComponentType = "device"
	ComponentTypeFile        ComponentType = "file"
	ComponentTypeFirmware    ComponentType = "firmware"
	ComponentTypeFramework   ComponentType = "framework"
	ComponentTypeLibrary     ComponentType = "library"
	ComponentTypeOS          ComponentType = "operating-system"
)

type Commit struct {
	UID       string              `json:"uid,omitempty" xml:"uid,omitempty"`
	URL       string              `json:"url,omitempty" xml:"url,omitempty"`
	Author    *IdentifiableAction `json:"author,omitempty" xml:"author,omitempty"`
	Committer *IdentifiableAction `json:"committer,omitempty" xml:"committer,omitempty"`
	Message   string              `json:"message,omitempty" xml:"message,omitempty"`
}

type Component struct {
	BOMRef             string                `json:"bom-ref,omitempty" xml:"bom-ref,attr,omitempty"`
	MIMEType           string                `json:"mime-type,omitempty" xml:"mime-type,attr,omitempty"`
	Type               ComponentType         `json:"type" xml:"type,attr"`
	Supplier           *OrganizationalEntity `json:"supplier,omitempty" xml:"supplier,omitempty"`
	Author             string                `json:"author,omitempty" xml:"author,omitempty"`
	Publisher          string                `json:"publisher,omitempty" xml:"publisher,omitempty"`
	Group              string                `json:"group,omitempty" xml:"group,omitempty"`
	Name               string                `json:"name" xml:"name"`
	Version            string                `json:"version,omitempty" xml:"version,omitempty"`
	Description        string                `json:"description,omitempty" xml:"description,omitempty"`
	Scope              Scope                 `json:"scope,omitempty" xml:"scope,omitempty"`
	Hashes             *[]Hash               `json:"hashes,omitempty" xml:"hashes>hash,omitempty"`
	Licenses           *Licenses             `json:"licenses,omitempty" xml:"licenses,omitempty"`
	Copyright          string                `json:"copyright,omitempty" xml:"copyright,omitempty"`
	CPE                string                `json:"cpe,omitempty" xml:"cpe,omitempty"`
	PackageURL         string                `json:"purl,omitempty" xml:"purl,omitempty"`
	SWID               *SWID                 `json:"swid,omitempty" xml:"swid,omitempty"`
	Modified           *bool                 `json:"modified,omitempty" xml:"modified,omitempty"`
	Pedigree           *Pedigree             `json:"pedigree,omitempty" xml:"pedigree,omitempty"`
	ExternalReferences *[]ExternalReference  `json:"externalReferences,omitempty" xml:"externalReferences>reference,omitempty"`
	Properties         *[]Property           `json:"properties,omitempty" xml:"properties>property,omitempty"`
	Components         *[]Component          `json:"components,omitempty" xml:"components>component,omitempty"`
	Evidence           *Evidence             `json:"evidence,omitempty" xml:"evidence,omitempty"`
	ReleaseNotes       *ReleaseNotes         `json:"releaseNotes,omitempty" xml:"releaseNotes,omitempty"`
}

type Composition struct {
	Aggregate    CompositionAggregate `json:"aggregate" xml:"aggregate"`
	Assemblies   *[]BOMReference      `json:"assemblies,omitempty" xml:"assemblies>assembly,omitempty"`
	Dependencies *[]BOMReference      `json:"dependencies,omitempty" xml:"dependencies>dependency,omitempty"`
}

type CompositionAggregate string

const (
	CompositionAggregateComplete                 CompositionAggregate = "complete"
	CompositionAggregateIncomplete               CompositionAggregate = "incomplete"
	CompositionAggregateIncompleteFirstPartyOnly CompositionAggregate = "incomplete_first_party_only"
	CompositionAggregateIncompleteThirdPartyOnly CompositionAggregate = "incomplete_third_party_only"
	CompositionAggregateUnknown                  CompositionAggregate = "unknown"
	CompositionAggregateNotSpecified             CompositionAggregate = "not_specified"
)

type Copyright struct {
	Text string `json:"text" xml:"-"`
}

func (c Copyright) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(c.Text, start)
}

func (c *Copyright) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var text string
	if err := d.DecodeElement(&text, &start); err != nil {
		return err
	}
	(*c).Text = text
	return nil
}

type Credits struct {
	Organizations *[]OrganizationalEntity  `json:"organizations,omitempty" xml:"organizations>organization,omitempty"`
	Individuals   *[]OrganizationalContact `json:"individuals,omitempty" xml:"individuals>individual,omitempty"`
}

type DataClassification struct {
	Flow           DataFlow `json:"flow" xml:"flow,attr"`
	Classification string   `json:"classification" xml:",innerxml"`
}

type DataFlow string

const (
	DataFlowBidirectional DataFlow = "bi-directional"
	DataFlowInbound       DataFlow = "inbound"
	DataFlowOutbound      DataFlow = "outbound"
	DataFlowUnknown       DataFlow = "unknown"
)

type Dependency struct {
	Ref          string        `xml:"ref,attr"`
	Dependencies *[]Dependency `xml:"dependency,omitempty"`
}

// dependencyJSON is temporarily used for marshalling and unmarshalling Dependency instances to and from JSON
type dependencyJSON struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func (d Dependency) MarshalJSON() ([]byte, error) {
	if d.Dependencies == nil || len(*d.Dependencies) == 0 {
		return json.Marshal(&dependencyJSON{
			Ref: d.Ref,
		})
	}

	dependencyRefs := make([]string, len(*d.Dependencies))
	for i, dependency := range *d.Dependencies {
		dependencyRefs[i] = dependency.Ref
	}

	return json.Marshal(&dependencyJSON{
		Ref:       d.Ref,
		DependsOn: dependencyRefs,
	})
}

func (d *Dependency) UnmarshalJSON(bytes []byte) error {
	dependency := new(dependencyJSON)
	if err := json.Unmarshal(bytes, dependency); err != nil {
		return err
	}
	d.Ref = dependency.Ref

	if len(dependency.DependsOn) == 0 {
		return nil
	}

	dependencies := make([]Dependency, len(dependency.DependsOn))
	for i, dep := range dependency.DependsOn {
		dependencies[i] = Dependency{
			Ref: dep,
		}
	}
	d.Dependencies = &dependencies

	return nil
}

type Diff struct {
	Text *AttachedText `json:"text,omitempty" xml:"text,omitempty"`
	URL  string        `json:"url,omitempty" xml:"url,omitempty"`
}

type Evidence struct {
	Licenses  *Licenses    `json:"licenses,omitempty" xml:"licenses,omitempty"`
	Copyright *[]Copyright `json:"copyright,omitempty" xml:"copyright>text,omitempty"`
}

type ExternalReference struct {
	URL     string                `json:"url" xml:"url"`
	Comment string                `json:"comment,omitempty" xml:"comment,omitempty"`
	Hashes  *[]Hash               `json:"hashes,omitempty" xml:"hashes>hash,omitempty"`
	Type    ExternalReferenceType `json:"type" xml:"type,attr"`
}

type ExternalReferenceType string

const (
	ERTypeAdvisories    ExternalReferenceType = "advisories"
	ERTypeBOM           ExternalReferenceType = "bom"
	ERTypeBuildMeta     ExternalReferenceType = "build-meta"
	ERTypeBuildSystem   ExternalReferenceType = "build-system"
	ERTypeChat          ExternalReferenceType = "chat"
	ERTypeDistribution  ExternalReferenceType = "distribution"
	ERTypeDocumentation ExternalReferenceType = "documentation"
	ERTypeLicense       ExternalReferenceType = "license"
	ERTypeMailingList   ExternalReferenceType = "mailing-list"
	ERTypeOther         ExternalReferenceType = "other"
	ERTypeIssueTracker  ExternalReferenceType = "issue-tracker"
	ERTypeReleaseNotes  ExternalReferenceType = "release-notes"
	ERTypeSocial        ExternalReferenceType = "social"
	ERTypeSupport       ExternalReferenceType = "support"
	ERTypeVCS           ExternalReferenceType = "vcs"
	ERTypeWebsite       ExternalReferenceType = "website"
)

type Hash struct {
	Algorithm HashAlgorithm `json:"alg" xml:"alg,attr"`
	Value     string        `json:"content" xml:",innerxml"`
}

type HashAlgorithm string

const (
	HashAlgoMD5         HashAlgorithm = "MD5"
	HashAlgoSHA1        HashAlgorithm = "SHA-1"
	HashAlgoSHA256      HashAlgorithm = "SHA-256"
	HashAlgoSHA384      HashAlgorithm = "SHA-384"
	HashAlgoSHA512      HashAlgorithm = "SHA-512"
	HashAlgoSHA3_256    HashAlgorithm = "SHA3-256"
	HashAlgoSHA3_512    HashAlgorithm = "SHA3-512"
	HashAlgoBlake2b_256 HashAlgorithm = "BLAKE2b-256"
	HashAlgoBlake2b_384 HashAlgorithm = "BLAKE2b-384"
	HashAlgoBlake2b_512 HashAlgorithm = "BLAKE2b-512"
	HashAlgoBlake3      HashAlgorithm = "BLAKE3"
)

type IdentifiableAction struct {
	Timestamp string `json:"timestamp,omitempty" xml:"timestamp,omitempty"`
	Name      string `json:"name,omitempty" xml:"name,omitempty"`
	EMail     string `json:"email,omitempty" xml:"email,omitempty"`
}

type ImpactAnalysisJustification string

const (
	IAJCodeNotPresent               ImpactAnalysisJustification = "code_not_present"
	IAJCodeNotReachable             ImpactAnalysisJustification = "code_not_reachable"
	IAJRequiresConfiguration        ImpactAnalysisJustification = "requires_configuration"
	IAJRequiresDependency           ImpactAnalysisJustification = "requires_dependency"
	IAJRequiresEnvironment          ImpactAnalysisJustification = "requires_environment"
	IAJProtectedByCompiler          ImpactAnalysisJustification = "protected_by_compiler"
	IAJProtectedAtRuntime           ImpactAnalysisJustification = "protected_at_runtime"
	IAJProtectedAtPerimeter         ImpactAnalysisJustification = "protected_at_perimeter"
	IAJProtectedByMitigatingControl ImpactAnalysisJustification = "protected_by_mitigating_control"
)

type ImpactAnalysisResponse string

const (
	IARCanNotFix           ImpactAnalysisResponse = "can_not_fix"
	IARWillNotFix          ImpactAnalysisResponse = "will_not_fix"
	IARUpdate              ImpactAnalysisResponse = "update"
	IARRollback            ImpactAnalysisResponse = "rollback"
	IARWorkaroundAvailable ImpactAnalysisResponse = "workaround_available"
)

type ImpactAnalysisState string

const (
	IASResolved             ImpactAnalysisState = "resolved"
	IASResolvedWithPedigree ImpactAnalysisState = "resolved_with_pedigree"
	IASExploitable          ImpactAnalysisState = "exploitable"
	IASInTriage             ImpactAnalysisState = "in_triage"
	IASFalsePositive        ImpactAnalysisState = "false_positive"
	IASNotAffected          ImpactAnalysisState = "not_affected"
)

type Issue struct {
	ID          string    `json:"id" xml:"id"`
	Name        string    `json:"name,omitempty" xml:"name,omitempty"`
	Description string    `json:"description" xml:"description"`
	Source      *Source   `json:"source,omitempty" xml:"source,omitempty"`
	References  *[]string `json:"references,omitempty" xml:"references>url,omitempty"`
	Type        IssueType `json:"type" xml:"type,attr"`
}

type IssueType string

const (
	IssueTypeDefect      IssueType = "defect"
	IssueTypeEnhancement IssueType = "enhancement"
	IssueTypeSecurity    IssueType = "security"
)

type License struct {
	ID   string        `json:"id,omitempty" xml:"id,omitempty"`
	Name string        `json:"name,omitempty" xml:"name,omitempty"`
	Text *AttachedText `json:"text,omitempty" xml:"text,omitempty"`
	URL  string        `json:"url,omitempty" xml:"url,omitempty"`
}

type Licenses []LicenseChoice

func (l Licenses) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	if len(l) == 0 {
		return nil
	}

	if err := e.EncodeToken(start); err != nil {
		return err
	}

	for _, choice := range l {
		if choice.License != nil && choice.Expression != "" {
			return fmt.Errorf("either license or expression must be set, but not both")
		}

		if choice.License != nil {
			if err := e.EncodeElement(choice.License, xml.StartElement{Name: xml.Name{Local: "license"}}); err != nil {
				return err
			}
		} else if choice.Expression != "" {
			if err := e.EncodeElement(choice.Expression, xml.StartElement{Name: xml.Name{Local: "expression"}}); err != nil {
				return err
			}
		}
	}

	return e.EncodeToken(start.End())
}

func (l *Licenses) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	licenses := make([]LicenseChoice, 0)

	for {
		token, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}

		switch tokenType := token.(type) {
		case xml.StartElement:
			if tokenType.Name.Local == "expression" {
				var expression string
				if err = d.DecodeElement(&expression, &tokenType); err != nil {
					return err
				}
				licenses = append(licenses, LicenseChoice{Expression: expression})
			} else if tokenType.Name.Local == "license" {
				var license License
				if err = d.DecodeElement(&license, &tokenType); err != nil {
					return err
				}
				licenses = append(licenses, LicenseChoice{License: &license})
			} else {
				return fmt.Errorf("unknown element: %s", tokenType.Name.Local)
			}
		}
	}

	*l = licenses
	return nil
}

type LicenseChoice struct {
	License    *License `json:"license,omitempty" xml:"-"`
	Expression string   `json:"expression,omitempty" xml:"-"`
}

type Metadata struct {
	Timestamp   string                   `json:"timestamp,omitempty" xml:"timestamp,omitempty"`
	Tools       *[]Tool                  `json:"tools,omitempty" xml:"tools>tool,omitempty"`
	Authors     *[]OrganizationalContact `json:"authors,omitempty" xml:"authors>author,omitempty"`
	Component   *Component               `json:"component,omitempty" xml:"component,omitempty"`
	Manufacture *OrganizationalEntity    `json:"manufacture,omitempty" xml:"manufacture,omitempty"`
	Supplier    *OrganizationalEntity    `json:"supplier,omitempty" xml:"supplier,omitempty"`
	Licenses    *Licenses                `json:"licenses,omitempty" xml:"licenses,omitempty"`
	Properties  *[]Property              `json:"properties,omitempty" xml:"properties>property,omitempty"`
}

type Note struct {
	Locale string       `json:"locale,omitempty" xml:"locale,omitempty"`
	Text   AttachedText `json:"text" xml:"text"`
}

type OrganizationalContact struct {
	Name  string `json:"name,omitempty" xml:"name,omitempty"`
	EMail string `json:"email,omitempty" xml:"email,omitempty"`
	Phone string `json:"phone,omitempty" xml:"phone,omitempty"`
}

type OrganizationalEntity struct {
	Name    string                   `json:"name" xml:"name"`
	URL     *[]string                `json:"url,omitempty" xml:"url,omitempty"`
	Contact *[]OrganizationalContact `json:"contact,omitempty" xml:"contact,omitempty"`
}

type Patch struct {
	Diff     *Diff     `json:"diff,omitempty" xml:"diff,omitempty"`
	Resolves *[]Issue  `json:"resolves,omitempty" xml:"resolves>issue,omitempty"`
	Type     PatchType `json:"type" xml:"type,attr"`
}

type PatchType string

const (
	PatchTypeBackport   PatchType = "backport"
	PatchTypeCherryPick PatchType = "cherry-pick"
	PatchTypeMonkey     PatchType = "monkey"
	PatchTypeUnofficial PatchType = "unofficial"
)

type Pedigree struct {
	Ancestors   *[]Component `json:"ancestors,omitempty" xml:"ancestors>component,omitempty"`
	Descendants *[]Component `json:"descendants,omitempty" xml:"descendants>component,omitempty"`
	Variants    *[]Component `json:"variants,omitempty" xml:"variants>component,omitempty"`
	Commits     *[]Commit    `json:"commits,omitempty" xml:"commits>commit,omitempty"`
	Patches     *[]Patch     `json:"patches,omitempty" xml:"patches>patch,omitempty"`
	Notes       string       `json:"notes,omitempty" xml:"notes,omitempty"`
}

type Property struct {
	Name  string `json:"name" xml:"name,attr"`
	Value string `json:"value" xml:",innerxml"`
}

type ReleaseNotes struct {
	Type          string      `json:"type" xml:"type"`
	Title         string      `json:"title,omitempty" xml:"title,omitempty"`
	FeaturedImage string      `json:"featuredImage,omitempty" xml:"featuredImage,omitempty"`
	SocialImage   string      `json:"socialImage,omitempty" xml:"socialImage,omitempty"`
	Description   string      `json:"description,omitempty" xml:"description,omitempty"`
	Timestamp     string      `json:"timestamp,omitempty" xml:"timestamp,omitempty"`
	Aliases       *[]string   `json:"aliases,omitempty" xml:"aliases>alias,omitempty"`
	Tags          *[]string   `json:"tags,omitempty" xml:"tags>tag,omitempty"`
	Resolves      *[]Issue    `json:"resolves,omitempty" xml:"resolves>issue,omitempty"`
	Notes         *[]Note     `json:"notes,omitempty" xml:"notes>note,omitempty"`
	Properties    *[]Property `json:"properties,omitempty" xml:"properties>property,omitempty"`
}

type Scope string

const (
	ScopeExcluded Scope = "excluded"
	ScopeOptional Scope = "optional"
	ScopeRequired Scope = "required"
)

type ScoringMethod string

const (
	ScoringMethodOther   ScoringMethod = "other"
	ScoringMethodCVSSv2  ScoringMethod = "CVSSv2"
	ScoringMethodCVSSv3  ScoringMethod = "CVSSv3"
	ScoringMethodCVSSv31 ScoringMethod = "CVSSv31"
	ScoringMethodOWASP   ScoringMethod = "OWASP"
)

type Service struct {
	BOMRef               string                `json:"bom-ref,omitempty" xml:"bom-ref,attr,omitempty"`
	Provider             *OrganizationalEntity `json:"provider,omitempty" xml:"provider,omitempty"`
	Group                string                `json:"group,omitempty" xml:"group,omitempty"`
	Name                 string                `json:"name" xml:"name"`
	Version              string                `json:"version,omitempty" xml:"version,omitempty"`
	Description          string                `json:"description,omitempty" xml:"description,omitempty"`
	Endpoints            *[]string             `json:"endpoints,omitempty" xml:"endpoints>endpoint,omitempty"`
	Authenticated        *bool                 `json:"authenticated,omitempty" xml:"authenticated,omitempty"`
	CrossesTrustBoundary *bool                 `json:"x-trust-boundary,omitempty" xml:"x-trust-boundary,omitempty"`
	Data                 *[]DataClassification `json:"data,omitempty" xml:"data>classification,omitempty"`
	Licenses             *Licenses             `json:"licenses,omitempty" xml:"licenses,omitempty"`
	ExternalReferences   *[]ExternalReference  `json:"externalReferences,omitempty" xml:"externalReferences>reference,omitempty"`
	Properties           *[]Property           `json:"properties,omitempty" xml:"properties>property,omitempty"`
	Services             *[]Service            `json:"services,omitempty" xml:"services>service,omitempty"`
	ReleaseNotes         *ReleaseNotes         `json:"releaseNotes,omitempty" xml:"releaseNotes,omitempty"`
}

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityNone     Severity = "none"
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Source struct {
	Name string `json:"name,omitempty" xml:"name,omitempty"`
	URL  string `json:"url,omitempty" xml:"url,omitempty"`
}

type SWID struct {
	Text       *AttachedText `json:"text,omitempty" xml:"text,omitempty"`
	URL        string        `json:"url,omitempty" xml:"url,attr,omitempty"`
	TagID      string        `json:"tagId" xml:"tagId,attr"`
	Name       string        `json:"name" xml:"name,attr"`
	Version    string        `json:"version,omitempty" xml:"version,attr,omitempty"`
	TagVersion *int          `json:"tagVersion,omitempty" xml:"tagVersion,attr,omitempty"`
	Patch      *bool         `json:"patch,omitempty" xml:"patch,attr,omitempty"`
}

type Tool struct {
	Vendor             string               `json:"vendor,omitempty" xml:"vendor,omitempty"`
	Name               string               `json:"name" xml:"name"`
	Version            string               `json:"version,omitempty" xml:"version,omitempty"`
	Hashes             *[]Hash              `json:"hashes,omitempty" xml:"hashes>hash,omitempty"`
	ExternalReferences *[]ExternalReference `json:"externalReferences,omitempty" xml:"externalReferences>reference,omitempty"`
}

type Vulnerability struct {
	BOMRef         string                    `json:"bom-ref,omitempty" xml:"bom-ref,attr,omitempty"`
	ID             string                    `json:"id" xml:"id"`
	Source         *Source                   `json:"source,omitempty" xml:"source,omitempty"`
	References     *[]VulnerabilityReference `json:"references,omitempty" xml:"references>reference,omitempty"`
	Ratings        *[]VulnerabilityRating    `json:"ratings,omitempty" xml:"ratings>rating,omitempty"`
	CWEs           *[]int                    `json:"cwes,omitempty" xml:"cwes>cwe,omitempty"`
	Description    string                    `json:"description,omitempty" xml:"description,omitempty"`
	Detail         string                    `json:"detail,omitempty" xml:"detail,omitempty"`
	Recommendation string                    `json:"recommendation,omitempty" xml:"recommendation,omitempty"`
	Advisories     *[]Advisory               `json:"advisories,omitempty" xml:"advisories>advisory,omitempty"`
	Created        string                    `json:"created,omitempty" xml:"created,omitempty"`
	Published      string                    `json:"published,omitempty" xml:"published,omitempty"`
	Updated        string                    `json:"updated,omitempty" xml:"updated,omitempty"`
	Credits        *Credits                  `json:"credits,omitempty" xml:"credits,omitempty"`
	Tools          *[]Tool                   `json:"tools,omitempty" xml:"tools>tool,omitempty"`
	Analysis       *VulnerabilityAnalysis    `json:"analysis,omitempty" xml:"analysis,omitempty"`
	Affects        *[]Affects                `json:"affects,omitempty" xml:"affects>target,omitempty"`
}

type VulnerabilityAnalysis struct {
	State         ImpactAnalysisState         `json:"state,omitempty" xml:"state,omitempty"`
	Justification ImpactAnalysisJustification `json:"justification,omitempty" xml:"justification,omitempty"`
	Response      *[]ImpactAnalysisResponse   `json:"response,omitempty" xml:"responses>response,omitempty"`
	Detail        string                      `json:"detail,omitempty" xml:"detail,omitempty"`
}

type VulnerabilityRating struct {
	Source        *Source       `json:"source,omitempty" xml:"source,omitempty"`
	Score         float64       `json:"score" xml:"score"`
	Severity      Severity      `json:"severity,omitempty" xml:"severity,omitempty"`
	Method        ScoringMethod `json:"method,omitempty" xml:"method,omitempty"`
	Vector        string        `json:"vector,omitempty" xml:"vector,omitempty"`
	Justification string        `json:"justification,omitempty" xml:"justification,omitempty"`
}

type VulnerabilityReference struct {
	ID     string  `json:"id,omitempty" xml:"id,omitempty"`
	Source *Source `json:"source,omitempty" xml:"source,omitempty"`
}

type VulnerabilityStatus string

const (
	VulnerabilityStatusUnknown     VulnerabilityStatus = "unknown"
	VulnerabilityStatusAffected    VulnerabilityStatus = "affected"
	VulnerabilityStatusNotAffected VulnerabilityStatus = "unaffected"
)
