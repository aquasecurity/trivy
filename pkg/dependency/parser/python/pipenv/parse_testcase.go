package pipenv

import "github.com/aquasecurity/trivy/pkg/dependency/types"

var (
	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	// graph doesn't contain information about location of dependency in lock file.
	// add locations manually
	pipenvNormal = []types.Library{
		{Name: "urllib3", Version: "1.24.2", Locations: []types.Location{{StartLine: 65, EndLine: 71}}},
		{Name: "requests", Version: "2.21.0", Locations: []types.Location{{StartLine: 57, EndLine: 64}}},
		{Name: "pyyaml", Version: "5.1", Locations: []types.Location{{StartLine: 40, EndLine: 56}}},
		{Name: "idna", Version: "2.8", Locations: []types.Location{{StartLine: 33, EndLine: 39}}},
		{Name: "chardet", Version: "3.0.4", Locations: []types.Location{{StartLine: 26, EndLine: 32}}},
		{Name: "certifi", Version: "2019.3.9", Locations: []types.Location{{StartLine: 19, EndLine: 25}}},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine bash
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml django djangorestframework
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	// graph doesn't contain information about location of dependency in lock file.
	// add locations manually
	pipenvDjango = []types.Library{
		{Name: "urllib3", Version: "1.24.2", Locations: []types.Location{{StartLine: 95, EndLine: 101}}},
		{Name: "sqlparse", Version: "0.3.0", Locations: []types.Location{{StartLine: 88, EndLine: 94}}},
		{Name: "requests", Version: "2.21.0", Locations: []types.Location{{StartLine: 80, EndLine: 87}}},
		{Name: "pyyaml", Version: "5.1", Locations: []types.Location{{StartLine: 63, EndLine: 79}}},
		{Name: "pytz", Version: "2019.1", Locations: []types.Location{{StartLine: 56, EndLine: 62}}},
		{Name: "idna", Version: "2.8", Locations: []types.Location{{StartLine: 49, EndLine: 55}}},
		{Name: "djangorestframework", Version: "3.9.3", Locations: []types.Location{{StartLine: 41, EndLine: 48}}},
		{Name: "django", Version: "2.2", Locations: []types.Location{{StartLine: 33, EndLine: 40}}},
		{Name: "chardet", Version: "3.0.4", Locations: []types.Location{{StartLine: 26, EndLine: 32}}},
		{Name: "certifi", Version: "2019.3.9", Locations: []types.Location{{StartLine: 19, EndLine: 25}}},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine bash
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml django djangorestframework six botocore python-dateutil simplejson setuptools pyasn1 awscli jinja2
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	// graph doesn't contain information about location of dependency in lock file.
	// add locations manually
	pipenvMany = []types.Library{
		{Name: "urllib3", Version: "1.24.2", Locations: []types.Location{{StartLine: 237, EndLine: 244}}},
		{Name: "sqlparse", Version: "0.3.0", Locations: []types.Location{{StartLine: 230, EndLine: 236}}},
		{Name: "six", Version: "1.12.0", Locations: []types.Location{{StartLine: 222, EndLine: 229}}},
		{Name: "simplejson", Version: "3.16.0", Locations: []types.Location{{StartLine: 204, EndLine: 221}}},
		{Name: "s3transfer", Version: "0.2.0", Locations: []types.Location{{StartLine: 197, EndLine: 203}}},
		{Name: "rsa", Version: "3.4.2", Locations: []types.Location{{StartLine: 190, EndLine: 196}}},
		{Name: "requests", Version: "2.21.0", Locations: []types.Location{{StartLine: 182, EndLine: 189}}},
		{Name: "pyyaml", Version: "3.13", Locations: []types.Location{{StartLine: 165, EndLine: 181}}},
		{Name: "pytz", Version: "2019.1", Locations: []types.Location{{StartLine: 158, EndLine: 164}}},
		{Name: "python-dateutil", Version: "2.8.0", Locations: []types.Location{{StartLine: 150, EndLine: 157}}},
		{Name: "pyasn1", Version: "0.4.5", Locations: []types.Location{{StartLine: 142, EndLine: 149}}},
		{Name: "markupsafe", Version: "1.1.1", Locations: []types.Location{{StartLine: 109, EndLine: 141}}},
		{Name: "jmespath", Version: "0.9.4", Locations: []types.Location{{StartLine: 102, EndLine: 108}}},
		{Name: "jinja2", Version: "2.10.1", Locations: []types.Location{{StartLine: 94, EndLine: 101}}},
		{Name: "idna", Version: "2.8", Locations: []types.Location{{StartLine: 87, EndLine: 93}}},
		{Name: "framework", Version: "0.1.0", Locations: []types.Location{{StartLine: 80, EndLine: 86}}},
		{Name: "docutils", Version: "0.14", Locations: []types.Location{{StartLine: 72, EndLine: 79}}},
		{Name: "djangorestframework", Version: "3.9.3", Locations: []types.Location{{StartLine: 64, EndLine: 71}}},
		{Name: "django", Version: "2.2", Locations: []types.Location{{StartLine: 56, EndLine: 63}}},
		{Name: "colorama", Version: "0.3.9", Locations: []types.Location{{StartLine: 49, EndLine: 55}}},
		{Name: "chardet", Version: "3.0.4", Locations: []types.Location{{StartLine: 42, EndLine: 48}}},
		{Name: "certifi", Version: "2019.3.9", Locations: []types.Location{{StartLine: 35, EndLine: 41}}},
		{Name: "botocore", Version: "1.12.137", Locations: []types.Location{{StartLine: 27, EndLine: 34}}},
		{Name: "awscli", Version: "1.16.147", Locations: []types.Location{{StartLine: 19, EndLine: 26}}},
	}
)
