package pip

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	requirementsFlask = []types.Library{
		{"click", "8.0.0", ""},
		{"Flask", "2.0.0", ""},
		{"itsdangerous", "2.0.0", ""},
		{"Jinja2", "3.0.0", ""},
		{"MarkupSafe", "2.0.0", ""},
		{"Werkzeug", "2.0.0", ""},
	}

	requirementsComments = []types.Library{
		{"click", "8.0.0", ""},
		{"Flask", "2.0.0", ""},
		{"Jinja2", "3.0.0", ""},
		{"MarkupSafe", "2.0.0", ""},
	}

	requirementsSpaces = []types.Library{
		{"click", "8.0.0", ""},
		{"Flask", "2.0.0", ""},
		{"itsdangerous", "2.0.0", ""},
		{"Jinja2", "3.0.0", ""},
	}

	requirementsNoVersion = []types.Library{
		{"Flask", "2.0.0", ""},
	}

	requirementsOperator = []types.Library{
		{"Django", "2.3.4", ""},
		{"SomeProject", "5.4", ""},
	}

	requirementsHash = []types.Library{
		{"FooProject", "1.2", ""},
		{"Jinja2", "3.0.0", ""},
	}

	requirementsHyphens = []types.Library{
		{"oauth2-client", "4.0.0", ""},
		{"python-gitlab", "2.0.0", ""},
	}
)
