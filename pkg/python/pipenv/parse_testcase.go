package pipenv

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	pipenvNormal = []types.Library{
		{Name: "urllib3", Version: "1.24.2"},
		{Name: "requests", Version: "2.21.0"},
		{Name: "pyyaml", Version: "5.1"},
		{Name: "idna", Version: "2.8"},
		{Name: "chardet", Version: "3.0.4"},
		{Name: "certifi", Version: "2019.3.9"},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine bash
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml django djangorestframework
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	pipenvDjango = []types.Library{
		{Name: "urllib3", Version: "1.24.2"},
		{Name: "sqlparse", Version: "0.3.0"},
		{Name: "requests", Version: "2.21.0"},
		{Name: "pyyaml", Version: "5.1"},
		{Name: "pytz", Version: "2019.1"},
		{Name: "idna", Version: "2.8"},
		{Name: "djangorestframework", Version: "3.9.3"},
		{Name: "django", Version: "2.2"},
		{Name: "chardet", Version: "3.0.4"},
		{Name: "certifi", Version: "2019.3.9"},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine bash
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml django djangorestframework six botocore python-dateutil simplejson setuptools pyasn1 awscli jinja2
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	pipenvMany = []types.Library{
		{Name: "urllib3", Version: "1.24.2"},
		{Name: "sqlparse", Version: "0.3.0"},
		{Name: "six", Version: "1.12.0"},
		{Name: "simplejson", Version: "3.16.0"},
		{Name: "s3transfer", Version: "0.2.0"},
		{Name: "rsa", Version: "3.4.2"},
		{Name: "requests", Version: "2.21.0"},
		{Name: "pyyaml", Version: "3.13"},
		{Name: "pytz", Version: "2019.1"},
		{Name: "python-dateutil", Version: "2.8.0"},
		{Name: "pyasn1", Version: "0.4.5"},
		{Name: "markupsafe", Version: "1.1.1"},
		{Name: "jmespath", Version: "0.9.4"},
		{Name: "jinja2", Version: "2.10.1"},
		{Name: "idna", Version: "2.8"},
		{Name: "framework", Version: "0.1.0"},
		{Name: "docutils", Version: "0.14"},
		{Name: "djangorestframework", Version: "3.9.3"},
		{Name: "django", Version: "2.2"},
		{Name: "colorama", Version: "0.3.9"},
		{Name: "chardet", Version: "3.0.4"},
		{Name: "certifi", Version: "2019.3.9"},
		{Name: "botocore", Version: "1.12.137"},
		{Name: "awscli", Version: "1.16.147"},
	}
)
