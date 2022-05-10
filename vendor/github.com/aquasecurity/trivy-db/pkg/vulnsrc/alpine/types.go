package alpine

type advisory struct {
	PkgName       string              `json:"name"`
	Secfixes      map[string][]string `json:"secfixes"`
	Apkurl        string              `json:"apkurl"`
	Archs         []string            `json:"archs"`
	Urlprefix     string              `json:"urlprefix"`
	Reponame      string              `json:"reponame"`
	Distroversion string              `json:"distroversion"`
}
