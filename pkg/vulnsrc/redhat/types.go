package redhat

type RedhatCVE struct {
	ThreatSeverity       string         `json:"threat_severity"`
	PublicDate           string         `json:"public_date"`
	Bugzilla             RedhatBugzilla `json:"bugzilla"`
	Cvss                 RedhatCvss     `json:"cvss"`
	Cvss3                RedhatCvss3    `json:"cvss3"`
	Iava                 string         `json:"iava"`
	Cwe                  string         `json:"cwe"`
	Statement            string         `json:"statement"`
	Acknowledgement      string         `json:"acknowledgement"`
	Mitigation           string         `json:"mitigation"`
	TempAffectedRelease  interface{}    `json:"affected_release"` // affected_release is array or object
	AffectedRelease      []RedhatAffectedRelease
	TempPackageState     interface{} `json:"package_state"` // package_state is array or object
	PackageState         []RedhatPackageState
	Name                 string `json:"name"`
	DocumentDistribution string `json:"document_distribution"`

	Details    []string `json:"details" gorm:"-"`
	References []string `json:"references" gorm:"-"`
}

type RedhatCVEAffectedReleaseArray struct {
	AffectedRelease []RedhatAffectedRelease `json:"affected_release"`
}

type RedhatCVEAffectedReleaseObject struct {
	AffectedRelease RedhatAffectedRelease `json:"affected_release"`
}

type RedhatCVEPackageStateArray struct {
	PackageState []RedhatPackageState `json:"package_state"`
}

type RedhatCVEPackageStateObject struct {
	PackageState RedhatPackageState `json:"package_state"`
}

type RedhatDetail struct {
	Detail string `sql:"type:text"`
}

type RedhatReference struct {
	Reference string `sql:"type:text"`
}

type RedhatBugzilla struct {
	Description string `json:"description" sql:"type:text"`
	BugzillaID  string `json:"id"`
	URL         string `json:"url"`
}

type RedhatCvss struct {
	CvssBaseScore     string `json:"cvss_base_score"`
	CvssScoringVector string `json:"cvss_scoring_vector"`
	Status            string `json:"status"`
}

type RedhatCvss3 struct {
	Cvss3BaseScore     string `json:"cvss3_base_score"`
	Cvss3ScoringVector string `json:"cvss3_scoring_vector"`
	Status             string `json:"status"`
}

type RedhatAffectedRelease struct {
	ProductName string `json:"product_name"`
	ReleaseDate string `json:"release_date"`
	Advisory    string `json:"advisory"`
	Package     string `json:"package"`
	Cpe         string `json:"cpe"`
}

type RedhatPackageState struct {
	ProductName string `json:"product_name"`
	FixState    string `json:"fix_state"`
	PackageName string `json:"package_name"`
	Cpe         string `json:"cpe"`
}
