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
		{Name: "atomicwrites", Version: "1.3.0"},
		{Name: "attrs", Version: "19.1.0"},
		{Name: "colorama", Version: "0.4.1"},
		{Name: "more-itertools", Version: "7.0.0"},
		{Name: "pluggy", Version: "0.11.0"},
		{Name: "py", Version: "1.8.0"},
		{Name: "pypi", Version: "2.1"},
		{Name: "pytest", Version: "3.10.1"},
		{Name: "six", Version: "1.12.0"},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add curl
	// curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
	// export PATH=/root/.poetry/bin/:$PATH
	// Use https://github.com/sdispater/poetry/blob/master/poetry.lock
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{\""$1"\", \""$2"\", \"\"},\n") }'
	poetryMany = []types.Library{
		{Name: "appdirs", Version: "1.4.3"},
		{Name: "aspy.yaml", Version: "1.2.0"},
		{Name: "atomicwrites", Version: "1.3.0"},
		{Name: "attrs", Version: "19.1.0"},
		{Name: "black", Version: "19.3b0"},
		{Name: "cachecontrol", Version: "0.12.5"},
		{Name: "cachy", Version: "0.2.0"},
		{Name: "certifi", Version: "2019.3.9"},
		{Name: "cfgv", Version: "1.6.0"},
		{Name: "chardet", Version: "3.0.4"},
		{Name: "cleo", Version: "0.6.8"},
		{Name: "click", Version: "7.0"},
		{Name: "colorama", Version: "0.4.1"},
		{Name: "configparser", Version: "3.7.4"},
		{Name: "contextlib2", Version: "0.5.5"},
		{Name: "coverage", Version: "4.5.3"},
		{Name: "enum34", Version: "1.1.6"},
		{Name: "filelock", Version: "3.0.10"},
		{Name: "funcsigs", Version: "1.0.2"},
		{Name: "functools32", Version: "3.2.3-2"},
		{Name: "futures", Version: "3.2.0"},
		{Name: "glob2", Version: "0.6"},
		{Name: "html5lib", Version: "1.0.1"},
		{Name: "httpretty", Version: "0.9.6"},
		{Name: "identify", Version: "1.4.3"},
		{Name: "idna", Version: "2.8"},
		{Name: "importlib-metadata", Version: "0.12"},
		{Name: "importlib-resources", Version: "1.0.2"},
		{Name: "jinja2", Version: "2.10.1"},
		{Name: "jsonschema", Version: "3.0.1"},
		{Name: "livereload", Version: "2.6.1"},
		{Name: "lockfile", Version: "0.12.2"},
		{Name: "markdown", Version: "3.0.1"},
		{Name: "markdown", Version: "3.1"},
		{Name: "markupsafe", Version: "1.1.1"},
		{Name: "mkdocs", Version: "1.0.4"},
		{Name: "mock", Version: "3.0.5"},
		{Name: "more-itertools", Version: "5.0.0"},
		{Name: "more-itertools", Version: "7.0.0"},
		{Name: "msgpack", Version: "0.6.1"},
		{Name: "nodeenv", Version: "1.3.3"},
		{Name: "packaging", Version: "19.0"},
		{Name: "pastel", Version: "0.1.0"},
		{Name: "pathlib2", Version: "2.3.3"},
		{Name: "pkginfo", Version: "1.5.0.1"},
		{Name: "pluggy", Version: "0.11.0"},
		{Name: "pre-commit", Version: "1.16.1"},
		{Name: "py", Version: "1.8.0"},
		{Name: "pygments", Version: "2.3.1"},
		{Name: "pygments", Version: "2.4.0"},
		{Name: "pygments-github-lexers", Version: "0.0.5"},
		{Name: "pylev", Version: "1.3.0"},
		{Name: "pymdown-extensions", Version: "6.0"},
		{Name: "pyparsing", Version: "2.4.0"},
		{Name: "pyrsistent", Version: "0.14.11"},
		{Name: "pytest", Version: "4.5.0"},
		{Name: "pytest-cov", Version: "2.7.1"},
		{Name: "pytest-mock", Version: "1.10.4"},
		{Name: "pytest-sugar", Version: "0.9.2"},
		{Name: "pyyaml", Version: "5.1"},
		{Name: "requests", Version: "2.21.0"},
		{Name: "requests", Version: "2.22.0"},
		{Name: "requests-toolbelt", Version: "0.8.0"},
		{Name: "scandir", Version: "1.10.0"},
		{Name: "shellingham", Version: "1.3.1"},
		{Name: "six", Version: "1.12.0"},
		{Name: "termcolor", Version: "1.1.0"},
		{Name: "toml", Version: "0.10.0"},
		{Name: "tomlkit", Version: "0.5.3"},
		{Name: "tornado", Version: "5.1.1"},
		{Name: "tox", Version: "3.11.1"},
		{Name: "typing", Version: "3.6.6"},
		{Name: "urllib3", Version: "1.24.3"},
		{Name: "urllib3", Version: "1.25.2"},
		{Name: "virtualenv", Version: "16.6.0"},
		{Name: "wcwidth", Version: "0.1.7"},
		{Name: "webencodings", Version: "0.5.1"},
		{Name: "zipp", Version: "0.5.1"},
	}

	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add curl
	// curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
	// export PATH=/root/.poetry/bin/:$PATH
	// poetry new web && cd web
	// poetry add flask
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{\""$1"\", \""$2"\", \"\"},\n") }'
	poetryFlask = []types.Library{
		{Name: "atomicwrites", Version: "1.3.0"},
		{Name: "attrs", Version: "19.1.0"},
		{Name: "click", Version: "7.0"},
		{Name: "colorama", Version: "0.4.1"},
		{Name: "flask", Version: "1.0.3"},
		{Name: "itsdangerous", Version: "1.1.0"},
		{Name: "jinja2", Version: "2.10.1"},
		{Name: "markupsafe", Version: "1.1.1"},
		{Name: "more-itertools", Version: "7.0.0"},
		{Name: "pluggy", Version: "0.11.0"},
		{Name: "py", Version: "1.8.0"},
		{Name: "pytest", Version: "3.10.1"},
		{Name: "six", Version: "1.12.0"},
		{Name: "werkzeug", Version: "0.15.4"},
	}
)
