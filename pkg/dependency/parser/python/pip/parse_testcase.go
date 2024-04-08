package pip

import "github.com/aquasecurity/trivy/pkg/dependency/types"

var (
	requirementsFlask = []types.Library{
		{Name: "click", Version: "8.0.0"},
		{Name: "Flask", Version: "2.0.0"},
		{Name: "itsdangerous", Version: "2.0.0"},
		{Name: "Jinja2", Version: "3.0.0"},
		{Name: "MarkupSafe", Version: "2.0.0"},
		{Name: "Werkzeug", Version: "2.0.0"},
	}

	requirementsComments = []types.Library{
		{Name: "click", Version: "8.0.0"},
		{Name: "Flask", Version: "2.0.0"},
		{Name: "Jinja2", Version: "3.0.0"},
		{Name: "MarkupSafe", Version: "2.0.0"},
	}

	requirementsSpaces = []types.Library{
		{Name: "click", Version: "8.0.0"},
		{Name: "Flask", Version: "2.0.0"},
		{Name: "itsdangerous", Version: "2.0.0"},
		{Name: "Jinja2", Version: "3.0.0"},
	}

	requirementsNoVersion = []types.Library{
		{Name: "Flask", Version: "2.0.0"},
	}

	requirementsOperator = []types.Library{
		{Name: "Django", Version: "2.3.4"},
		{Name: "SomeProject", Version: "5.4"},
	}

	requirementsHash = []types.Library{
		{Name: "FooProject", Version: "1.2"},
		{Name: "Jinja2", Version: "3.0.0"},
	}

	requirementsHyphens = []types.Library{
		{Name: "oauth2-client", Version: "4.0.0"},
		{Name: "python-gitlab", Version: "2.0.0"},
	}

	requirementsExtras = []types.Library{
		{Name: "pyjwt", Version: "2.1.0"},
		{Name: "celery", Version: "4.4.7"},
	}

	requirementsUtf16le = []types.Library{
		{Name: "attrs", Version: "20.3.0"},
	}
)
