package poetry

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add curl
	// curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
	// export PATH=/root/.poetry/bin/:$PATH
	// poetry new normal && cd normal
	// poetry add pypi
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{\""$1"\", \""$2"\", \"\"},\n") }'
	poetryNormal = []types.Library{
		{"atomicwrites", "1.3.0", ""},
		{"attrs", "19.1.0", ""},
		{"colorama", "0.4.1", ""},
		{"more-itertools", "7.0.0", ""},
		{"pluggy", "0.11.0", ""},
		{"py", "1.8.0", ""},
		{"pypi", "2.1", ""},
		{"pytest", "3.10.1", ""},
		{"six", "1.12.0", ""},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add curl
	// curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
	// export PATH=/root/.poetry/bin/:$PATH
	// Use https://github.com/sdispater/poetry/blob/master/poetry.lock
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{\""$1"\", \""$2"\", \"\"},\n") }'
	poetryMany = []types.Library{
		{"appdirs", "1.4.3", ""},
		{"aspy.yaml", "1.2.0", ""},
		{"atomicwrites", "1.3.0", ""},
		{"attrs", "19.1.0", ""},
		{"black", "19.3b0", ""},
		{"cachecontrol", "0.12.5", ""},
		{"cachy", "0.2.0", ""},
		{"certifi", "2019.3.9", ""},
		{"cfgv", "1.6.0", ""},
		{"chardet", "3.0.4", ""},
		{"cleo", "0.6.8", ""},
		{"click", "7.0", ""},
		{"colorama", "0.4.1", ""},
		{"configparser", "3.7.4", ""},
		{"contextlib2", "0.5.5", ""},
		{"coverage", "4.5.3", ""},
		{"enum34", "1.1.6", ""},
		{"filelock", "3.0.10", ""},
		{"funcsigs", "1.0.2", ""},
		{"functools32", "3.2.3-2", ""},
		{"futures", "3.2.0", ""},
		{"glob2", "0.6", ""},
		{"html5lib", "1.0.1", ""},
		{"httpretty", "0.9.6", ""},
		{"identify", "1.4.3", ""},
		{"idna", "2.8", ""},
		{"importlib-metadata", "0.12", ""},
		{"importlib-resources", "1.0.2", ""},
		{"jinja2", "2.10.1", ""},
		{"jsonschema", "3.0.1", ""},
		{"livereload", "2.6.1", ""},
		{"lockfile", "0.12.2", ""},
		{"markdown", "3.0.1", ""},
		{"markdown", "3.1", ""},
		{"markupsafe", "1.1.1", ""},
		{"mkdocs", "1.0.4", ""},
		{"mock", "3.0.5", ""},
		{"more-itertools", "5.0.0", ""},
		{"more-itertools", "7.0.0", ""},
		{"msgpack", "0.6.1", ""},
		{"nodeenv", "1.3.3", ""},
		{"packaging", "19.0", ""},
		{"pastel", "0.1.0", ""},
		{"pathlib2", "2.3.3", ""},
		{"pkginfo", "1.5.0.1", ""},
		{"pluggy", "0.11.0", ""},
		{"pre-commit", "1.16.1", ""},
		{"py", "1.8.0", ""},
		{"pygments", "2.3.1", ""},
		{"pygments", "2.4.0", ""},
		{"pygments-github-lexers", "0.0.5", ""},
		{"pylev", "1.3.0", ""},
		{"pymdown-extensions", "6.0", ""},
		{"pyparsing", "2.4.0", ""},
		{"pyrsistent", "0.14.11", ""},
		{"pytest", "4.5.0", ""},
		{"pytest-cov", "2.7.1", ""},
		{"pytest-mock", "1.10.4", ""},
		{"pytest-sugar", "0.9.2", ""},
		{"pyyaml", "5.1", ""},
		{"requests", "2.21.0", ""},
		{"requests", "2.22.0", ""},
		{"requests-toolbelt", "0.8.0", ""},
		{"scandir", "1.10.0", ""},
		{"shellingham", "1.3.1", ""},
		{"six", "1.12.0", ""},
		{"termcolor", "1.1.0", ""},
		{"toml", "0.10.0", ""},
		{"tomlkit", "0.5.3", ""},
		{"tornado", "5.1.1", ""},
		{"tox", "3.11.1", ""},
		{"typing", "3.6.6", ""},
		{"urllib3", "1.24.3", ""},
		{"urllib3", "1.25.2", ""},
		{"virtualenv", "16.6.0", ""},
		{"wcwidth", "0.1.7", ""},
		{"webencodings", "0.5.1", ""},
		{"zipp", "0.5.1", ""},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add curl
	// curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
	// export PATH=/root/.poetry/bin/:$PATH
	// poetry new web && cd web
	// poetry add flask
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{\""$1"\", \""$2"\", \"\"},\n") }'
	poetryFlask = []types.Library{
		{"atomicwrites", "1.3.0", ""},
		{"attrs", "19.1.0", ""},
		{"click", "7.0", ""},
		{"colorama", "0.4.1", ""},
		{"flask", "1.0.3", ""},
		{"itsdangerous", "1.1.0", ""},
		{"jinja2", "2.10.1", ""},
		{"markupsafe", "1.1.1", ""},
		{"more-itertools", "7.0.0", ""},
		{"pluggy", "0.11.0", ""},
		{"py", "1.8.0", ""},
		{"pytest", "3.10.1", ""},
		{"six", "1.12.0", ""},
		{"werkzeug", "0.15.4", ""},
	}
)
