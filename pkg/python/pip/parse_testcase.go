package pip

import "github.com/aquasecurity/go-dep-parser/pkg/types"

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
)
