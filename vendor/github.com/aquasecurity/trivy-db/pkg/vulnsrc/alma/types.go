package alma

type Erratum struct {
	ID           OID         `json:"_id"`
	BsRepoID     OID         `json:"bs_repo_id"`
	UpdateinfoID string      `json:"updateinfo_id"`
	Description  string      `json:"description"`
	Fromstr      string      `json:"fromstr"`
	IssuedDate   Date        `json:"issued_date"`
	Pkglist      Pkglist     `json:"pkglist"`
	Pushcount    string      `json:"pushcount"`
	References   []Reference `json:"references"`
	Release      string      `json:"release"`
	Rights       string      `json:"rights"`
	Severity     string      `json:"severity"`
	Solution     string      `json:"solution"`
	Status       string      `json:"status"`
	Summary      string      `json:"summary"`
	Title        string      `json:"title"`
	Type         string      `json:"type"`
	UpdatedDate  Date        `json:"updated_date"`
	Version      string      `json:"version"`
}

type OID struct {
	OID string `json:"$oid,omitempty"`
}

type Date struct {
	Date int64 `json:"$date"`
}

type Pkglist struct {
	Name      string    `json:"name"`
	Shortname string    `json:"shortname"`
	Packages  []Package `json:"packages"`
	Module    Module    `json:"module"`
}

type Package struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	Release         string      `json:"release"`
	Epoch           string      `json:"epoch"`
	Arch            string      `json:"arch"`
	Src             string      `json:"src"`
	Filename        string      `json:"filename"`
	Sum             string      `json:"sum"`
	SumType         interface{} `json:"sum_type"`
	RebootSuggested int         `json:"reboot_suggested"`
}

type Module struct {
	Stream  string `json:"stream,omitempty"`
	Name    string `json:"name,omitempty"`
	Version int64  `json:"version,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Context string `json:"context,omitempty"`
}

type Reference struct {
	Href  string `json:"href"`
	Type  string `json:"type"`
	ID    string `json:"id"`
	Title string `json:"title"`
}
