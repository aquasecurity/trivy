package nvd

type NVD struct {
	CVEItems []Item `json:"CVE_Items"`
}

type Item struct {
	Cve    Cve
	Impact Impact
}

type Cve struct {
	Meta        Meta `json:"CVE_data_meta"`
	References  References
	Description Description
}

type Meta struct {
	ID string
}

type Impact struct {
	BaseMetricV2 BaseMetricV2
	BaseMetricV3 BaseMetricV3
}

type BaseMetricV2 struct {
	Severity string
}

type BaseMetricV3 struct {
	CvssV3 CvssV3
}

type CvssV3 struct {
	BaseSeverity string
}

type References struct {
	ReferenceDataList []ReferenceData `json:"reference_data"`
}
type ReferenceData struct {
	Name      string
	Refsource string
	URL       string
}

type Description struct {
	DescriptionDataList []DescriptionData `json:"description_data"`
}

type DescriptionData struct {
	Lang  string
	Value string
}
