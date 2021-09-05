package hook

type Type string

const (
	PythonPkg Type = "python-pkg"
	PkgJson   Type = "pacakgejson"
	GemSpec   Type = "gemspec"
)
