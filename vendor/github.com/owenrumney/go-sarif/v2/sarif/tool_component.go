package sarif

import (
	"time"
)

// ToolComponent ...
type ToolComponent struct {
	AssociatedComponent                         *ToolComponentReference              `json:"associatedComponent,omitempty"`
	Contents                                    []interface{}                        `json:"contents,omitempty"`
	DottedQuadFileVersion                       *string                              `json:"dottedQuadFileVersion,omitempty"`
	DownloadURI                                 *string                              `json:"downloadUri,omitempty"`
	FullDescription                             *MultiformatMessageString            `json:"fullDescription,omitempty"`
	FullName                                    *string                              `json:"fullName,omitempty"`
	GlobalMessageStrings                        map[string]*MultiformatMessageString `json:"globalMessageStrings,omitempty"`
	GUID                                        *string                              `json:"guid,omitempty"`
	InformationURI                              *string                              `json:"informationUri,omitempty"`
	IsComprehensive                             *bool                                `json:"isComprehensive,omitempty"`
	Language                                    *string                              `json:"language,omitempty"`
	LocalizedDataSemanticVersion                *string                              `json:"localizedDataSemanticVersion,omitempty"`
	Locations                                   []*ArtifactLocation                  `json:"locations,omitempty"`
	MinimumRequiredLocalizedDataSemanticVersion *string                              `json:"minimumRequiredLocalizedDataSemanticVersion,omitempty"`
	Name                                        string                               `json:"name"`
	Notifications                               []*ReportingDescriptor               `json:"notifications,omitempty"`
	Organization                                *string                              `json:"organization,omitempty"`
	Product                                     *string                              `json:"product,omitempty"`
	ProductSuite                                *string                              `json:"productSuite,omitempty"`
	ReleaseDateUtc                              *time.Time                           `json:"releaseDateUtc,omitempty"`
	Rules                                       []*ReportingDescriptor               `json:"rules"`
	SemanticVersion                             *string                              `json:"semanticVersion,omitempty"`
	ShortDescription                            *MultiformatMessageString            `json:"shortDescription,omitempty"`
	SupportedTaxonomies                         []*ToolComponentReference            `json:"supportedTaxonomies,omitempty"`
	Taxa                                        []*ReportingDescriptor               `json:"taxa,omitempty"`
	TranslationMetadata                         *TranslationMetadata                 `json:"translationMetadata,omitempty"` // The tool component version, in whatever format the component natively provides.
	Version                                     *string                              `json:"version,omitempty"`
	PropertyBag
}

// NewDriver creates a new Driver and returns a pointer to it
func NewDriver(name string) *ToolComponent {
	return &ToolComponent{
		Name:  name,
		Rules: []*ReportingDescriptor{},
	}
}

// NewVersionedDriver creates a new VersionedDriver and returns a pointer to it
func NewVersionedDriver(name, version string) *ToolComponent {
	return &ToolComponent{
		Name:    name,
		Version: &version,
		Rules:   []*ReportingDescriptor{},
	}
}

// WithVersion specifies tool version, in whatever format it natively provides. Returns updated driver.
func (driver *ToolComponent) WithVersion(version string) *ToolComponent {
	driver.Version = &version
	return driver
}

func (driver *ToolComponent) getOrCreateRule(rule *ReportingDescriptor) uint {
	for i, r := range driver.Rules {
		if r.ID == rule.ID {
			return uint(i)
		}
	}
	driver.Rules = append(driver.Rules, rule)
	return uint(len(driver.Rules) - 1)
}

// WithInformationURI sets the InformationURI
func (driver *ToolComponent) WithInformationURI(informationURI string) *ToolComponent {
	driver.InformationURI = &informationURI
	return driver
}

// WithNotifications sets the Notifications
func (driver *ToolComponent) WithNotifications(notifications []*ReportingDescriptor) *ToolComponent {
	driver.Notifications = notifications
	return driver
}

// AddNotification ...
func (driver *ToolComponent) AddNotification(notification *ReportingDescriptor) {
	driver.Notifications = append(driver.Notifications, notification)
}

// WithRules sets the Rules
func (driver *ToolComponent) WithRules(rules []*ReportingDescriptor) *ToolComponent {
	for _, rule := range rules {
		driver.getOrCreateRule(rule)
	}
	return driver
}

// AddRule ...
func (driver *ToolComponent) AddRule(rule *ReportingDescriptor) {
	driver.getOrCreateRule(rule)

}

// WithTaxa sets the Taxa
func (driver *ToolComponent) WithTaxa(taxa []*ReportingDescriptor) *ToolComponent {
	driver.Taxa = taxa
	return driver
}

// AddTaxa adds a single Taxa to the Taxa slice
func (driver *ToolComponent) AddTaxa(taxa *ReportingDescriptor) {
	driver.Taxa = append(driver.Taxa, taxa)
}

// WithAssociatedComponent adds an associated component to the driver
func (driver *ToolComponent) WithAssociatedComponent(associatedComponent *ToolComponentReference) *ToolComponent {
	driver.AssociatedComponent = associatedComponent
	return driver
}

// WithContents sets the contents slice to the provided value
func (driver *ToolComponent) WithContents(contents []interface{}) *ToolComponent {
	driver.Contents = contents
	return driver
}

// AddContent adds a single content object to the Contents slice
func (driver *ToolComponent) AddContent(content interface{}) {
	driver.Contents = append(driver.Contents, content)
}

// WithDottedQuadFileVersion ...
func (driver *ToolComponent) WithDottedQuadFileVersion(version string) *ToolComponent {
	driver.DottedQuadFileVersion = &version
	return driver
}

// WithDownloadURI ...
func (driver *ToolComponent) WithDownloadURI(downloadURI string) *ToolComponent {
	driver.DownloadURI = &downloadURI
	return driver
}

// WithFullDescription ...
func (driver *ToolComponent) WithFullDescription(description *MultiformatMessageString) *ToolComponent {
	driver.FullDescription = description
	return driver
}

// WithFullName ...
func (driver *ToolComponent) WithFullName(fullName string) *ToolComponent {
	driver.FullName = &fullName
	return driver
}

// WithGlobalMessageStrings ...
func (driver *ToolComponent) WithGlobalMessageStrings(messageStrings map[string]*MultiformatMessageString) *ToolComponent {
	driver.GlobalMessageStrings = messageStrings
	return driver
}

// WithGUID ...
func (driver *ToolComponent) WithGUID(guid string) *ToolComponent {
	driver.GUID = &guid
	return driver
}

// WithIsComprehensive ...
func (driver *ToolComponent) WithIsComprehensive(isComprehensive bool) *ToolComponent {
	driver.IsComprehensive = &isComprehensive
	return driver
}

// WithLanguage ...
func (driver *ToolComponent) WithLanguage(language string) *ToolComponent {
	driver.Language = &language
	return driver
}

// WithLocalizedDataSemanticVersion ...
func (driver *ToolComponent) WithLocalizedDataSemanticVersion(version string) *ToolComponent {
	driver.LocalizedDataSemanticVersion = &version
	return driver
}

// WithLocations ...
func (driver *ToolComponent) WithLocations(locations []*ArtifactLocation) *ToolComponent {
	driver.Locations = locations
	return driver
}

// AddLocation ...
func (driver *ToolComponent) AddLocation(location *ArtifactLocation) {
	driver.Locations = append(driver.Locations, location)
}

// WithMinimumRequiredLocalizedDataSemanticVersion ...
func (driver *ToolComponent) WithMinimumRequiredLocalizedDataSemanticVersion(version string) *ToolComponent {
	driver.MinimumRequiredLocalizedDataSemanticVersion = &version
	return driver
}

// WithOrganization ...
func (driver *ToolComponent) WithOrganization(organization string) *ToolComponent {
	driver.Organization = &organization
	return driver
}

// WithProduct ...
func (driver *ToolComponent) WithProduct(product string) *ToolComponent {
	driver.Product = &product
	return driver
}

// WithProductSuite ...
func (driver *ToolComponent) WithProductSuite(suite string) *ToolComponent {
	driver.ProductSuite = &suite
	return driver
}

// WithReleaseDateUTC ...
func (driver *ToolComponent) WithReleaseDateUTC(releaseDate *time.Time) *ToolComponent {
	driver.ReleaseDateUtc = releaseDate
	return driver
}

// WithSemanticVersion ...
func (driver *ToolComponent) WithSemanticVersion(version string) *ToolComponent {
	driver.SemanticVersion = &version
	return driver
}

// WithShortDescription ...
func (driver *ToolComponent) WithShortDescription(description *MultiformatMessageString) *ToolComponent {
	driver.ShortDescription = description
	return driver
}

// WithSupportedTaxonomies ...
func (driver *ToolComponent) WithSupportedTaxonomies(taxonomies []*ToolComponentReference) *ToolComponent {
	driver.SupportedTaxonomies = taxonomies
	return driver
}

// AddSupportedTaxonomie ...
func (driver *ToolComponent) AddSupportedTaxonomie(taxonomy *ToolComponentReference) {
	driver.SupportedTaxonomies = append(driver.SupportedTaxonomies, taxonomy)
}

// WithTranslationMetadata ...
func (driver *ToolComponent) WithTranslationMetadata(metadata *TranslationMetadata) *ToolComponent {
	driver.TranslationMetadata = metadata
	return driver
}

func (driver *ToolComponent) getRuleIndex(id *string) int {
	for i, rule := range driver.Rules {
		if rule.ID == *id {
			return i
		}
	}
	return -1
}
