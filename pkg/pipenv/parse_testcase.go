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
		{"urllib3", "1.24.2", ""},
		{"requests", "2.21.0", ""},
		{"pyyaml", "5.1", ""},
		{"idna", "2.8", ""},
		{"chardet", "3.0.4", ""},
		{"certifi", "2019.3.9", ""},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine bash
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml django djangorestframework
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	pipenvDjango = []types.Library{
		{"urllib3", "1.24.2", ""},
		{"sqlparse", "0.3.0", ""},
		{"requests", "2.21.0", ""},
		{"pyyaml", "5.1", ""},
		{"pytz", "2019.1", ""},
		{"idna", "2.8", ""},
		{"djangorestframework", "3.9.3", ""},
		{"django", "2.2", ""},
		{"chardet", "3.0.4", ""},
		{"certifi", "2019.3.9", ""},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine bash
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml django djangorestframework six botocore python-dateutil simplejson setuptools pyasn1 awscli jinja2
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	pipenvMany = []types.Library{
		{"urllib3", "1.24.2", ""},
		{"sqlparse", "0.3.0", ""},
		{"six", "1.12.0", ""},
		{"simplejson", "3.16.0", ""},
		{"s3transfer", "0.2.0", ""},
		{"rsa", "3.4.2", ""},
		{"requests", "2.21.0", ""},
		{"pyyaml", "3.13", ""},
		{"pytz", "2019.1", ""},
		{"python-dateutil", "2.8.0", ""},
		{"pyasn1", "0.4.5", ""},
		{"markupsafe", "1.1.1", ""},
		{"jmespath", "0.9.4", ""},
		{"jinja2", "2.10.1", ""},
		{"idna", "2.8", ""},
		{"framework", "0.1.0", ""},
		{"docutils", "0.14", ""},
		{"djangorestframework", "3.9.3", ""},
		{"django", "2.2", ""},
		{"colorama", "0.3.9", ""},
		{"chardet", "3.0.4", ""},
		{"certifi", "2019.3.9", ""},
		{"botocore", "1.12.137", ""},
		{"awscli", "1.16.147", ""},
	}
)
