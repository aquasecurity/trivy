package pip

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

var (
	requirementsCompatibleVersions = []ftypes.Package{
		{
			Name:    "keyring",
			Version: "4.1.1",
			Locations: []ftypes.Location{
				{
					StartLine: 1,
					EndLine:   1,
				},
			},
		},
		{
			Name:    "Mopidy-Dirble",
			Version: "1.1",
			Locations: []ftypes.Location{
				{
					StartLine: 2,
					EndLine:   2,
				},
			},
		},
		{
			Name:    "python-gitlab",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 3,
					EndLine:   3,
				},
			},
		},
	}
	requirementsFlask = []ftypes.Package{
		{
			Name:    "click",
			Version: "8.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 1,
					EndLine:   1,
				},
			},
		},
		{
			Name:    "Flask",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 2,
					EndLine:   2,
				},
			},
		},
		{
			Name:    "itsdangerous",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 3,
					EndLine:   3,
				},
			},
		},
		{
			Name:    "Jinja2",
			Version: "3.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 4,
					EndLine:   4,
				},
			},
		},
		{
			Name:    "MarkupSafe",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 5,
					EndLine:   5,
				},
			},
		},
		{
			Name:    "Werkzeug",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 6,
					EndLine:   6,
				},
			},
		},
	}

	requirementsComments = []ftypes.Package{
		{
			Name:    "click",
			Version: "8.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 4,
					EndLine:   4,
				},
			},
		},
		{
			Name:    "Flask",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 5,
					EndLine:   5,
				},
			},
		},
		{
			Name:    "Jinja2",
			Version: "3.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 6,
					EndLine:   6,
				},
			},
		},
		{
			Name:    "MarkupSafe",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 7,
					EndLine:   7,
				},
			},
		},
	}

	requirementsSpaces = []ftypes.Package{
		{
			Name:    "click",
			Version: "8.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 1,
					EndLine:   1,
				},
			},
		},
		{
			Name:    "Flask",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 2,
					EndLine:   2,
				},
			},
		},
		{
			Name:    "itsdangerous",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 3,
					EndLine:   3,
				},
			},
		},
		{
			Name:    "Jinja2",
			Version: "3.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 5,
					EndLine:   5,
				},
			},
		},
	}

	requirementsNoVersion = []ftypes.Package{
		{
			Name:    "Flask",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 1,
					EndLine:   1,
				},
			},
		},
	}

	requirementsOperator = []ftypes.Package{
		{
			Name:    "Django",
			Version: "2.3.4",
			Locations: []ftypes.Location{
				{
					StartLine: 4,
					EndLine:   4,
				},
			},
		},
		{
			Name:    "SomeProject",
			Version: "5.4",
			Locations: []ftypes.Location{
				{
					StartLine: 5,
					EndLine:   5,
				},
			},
		},
	}

	requirementsHash = []ftypes.Package{
		{
			Name:    "FooProject",
			Version: "1.2",
			Locations: []ftypes.Location{
				{
					StartLine: 1,
					EndLine:   1,
				},
			},
		},
		{
			Name:    "Jinja2",
			Version: "3.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 4,
					EndLine:   4,
				},
			},
		},
	}

	requirementsHyphens = []ftypes.Package{
		{
			Name:    "oauth2-client",
			Version: "4.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 1,
					EndLine:   1,
				},
			},
		},
		{
			Name:    "python-gitlab",
			Version: "2.0.0",
			Locations: []ftypes.Location{
				{
					StartLine: 2,
					EndLine:   2,
				},
			},
		},
	}

	requirementsExtras = []ftypes.Package{
		{
			Name:    "pyjwt",
			Version: "2.1.0",
			Locations: []ftypes.Location{
				{
					StartLine: 1,
					EndLine:   1,
				},
			},
		},
		{
			Name:    "celery",
			Version: "4.4.7",
			Locations: []ftypes.Location{
				{
					StartLine: 2,
					EndLine:   2,
				},
			},
		},
	}

	requirementsUtf16le = []ftypes.Package{
		{
			Name:    "attrs",
			Version: "20.3.0",
			Locations: []ftypes.Location{
				{
					StartLine: 1,
					EndLine:   1,
				},
			},
		},
	}
)
