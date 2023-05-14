package types

// CycloneDX re-defines only necessary fields from cyclondx/cyclonedx-go
// cf. https://github.com/CycloneDX/cyclonedx-go/blob/de6bc07025d148badc8f6699ccb556744a5f4070/cyclonedx.go#L58-L77
//
// The encoding/xml package that cyclondx-go depends on cannot be imported due to some limitations in TinyGo.
// cf. https://tinygo.org/docs/reference/lang-support/stdlib/
type CycloneDX struct {
	// JSON specific fields
	BOMFormat   string      `json:"bomFormat" xml:"-"`
	SpecVersion SpecVersion `json:"specVersion" xml:"-"`

	SerialNumber string      `json:"serialNumber,omitempty" xml:"serialNumber,attr,omitempty"`
	Version      int         `json:"version" xml:"version,attr"`
	Metadata     Metadata    `json:"metadata,omitempty" xml:"metadata,omitempty"`
	Components   []Component `json:"components,omitempty" xml:"components>component,omitempty"`
}

type Metadata struct {
	Timestamp string    `json:"timestamp,omitempty" xml:"timestamp,omitempty"`
	Component Component `json:"component,omitempty" xml:"component,omitempty"`
}

type Component struct {
	BOMRef     string        `json:"bom-ref,omitempty" xml:"bom-ref,attr,omitempty"`
	MIMEType   string        `json:"mime-type,omitempty" xml:"mime-type,attr,omitempty"`
	Type       ComponentType `json:"type" xml:"type,attr"`
	Name       string        `json:"name" xml:"name"`
	Version    string        `json:"version,omitempty" xml:"version,omitempty"`
	PackageURL string        `json:"purl,omitempty" xml:"purl,omitempty"`
}

type (
	ComponentType string
	SpecVersion   int
)
