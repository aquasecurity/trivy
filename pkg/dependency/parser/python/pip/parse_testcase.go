package pip

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

var (
	requirementsFlask = []ftypes.Package{
		{Name: "click", Version: "8.0.0"},
		{Name: "Flask", Version: "2.0.0"},
		{Name: "itsdangerous", Version: "2.0.0"},
		{Name: "Jinja2", Version: "3.0.0"},
		{Name: "MarkupSafe", Version: "2.0.0"},
		{Name: "Werkzeug", Version: "2.0.0"},
	}

	requirementsComments = []ftypes.Package{
		{Name: "click", Version: "8.0.0"},
		{Name: "Flask", Version: "2.0.0"},
		{Name: "Jinja2", Version: "3.0.0"},
		{Name: "MarkupSafe", Version: "2.0.0"},
	}

	requirementsSpaces = []ftypes.Package{
		{Name: "click", Version: "8.0.0"},
		{Name: "Flask", Version: "2.0.0"},
		{Name: "itsdangerous", Version: "2.0.0"},
		{Name: "Jinja2", Version: "3.0.0"},
	}

	requirementsNoVersion = []ftypes.Package{
		{Name: "Flask", Version: "2.0.0"},
	}

	requirementsOperator = []ftypes.Package{
		{Name: "Django", Version: "2.3.4"},
		{Name: "SomeProject", Version: "5.4"},
	}

	requirementsHash = []ftypes.Package{
		{Name: "FooProject", Version: "1.2"},
		{Name: "Jinja2", Version: "3.0.0"},
	}

	requirementsHyphens = []ftypes.Package{
		{Name: "oauth2-client", Version: "4.0.0"},
		{Name: "python-gitlab", Version: "2.0.0"},
	}

	requirementsExtras = []ftypes.Package{
		{Name: "pyjwt", Version: "2.1.0"},
		{Name: "celery", Version: "4.4.7"},
	}

	requirementsUtf16le = []ftypes.Package{
		{Name: "attrs", Version: "20.3.0"},
	}
)
