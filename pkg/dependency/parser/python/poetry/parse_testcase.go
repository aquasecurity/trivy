package poetry

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

var (
	// docker run --name poetry --rm -it python@sha256:e1141f10176d74d1a0e87a7c0a0a5a98dd98ec5ac12ce867768f40c6feae2fd9 sh
	// apk add curl
	// curl -sSL https://install.python-poetry.org | POETRY_VERSION=1.1.7 python3 -
	// export PATH=/root/.local/bin:$PATH
	// poetry new normal && cd normal
	// poetry add pypi@2.1
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\"},\n") }'
	poetryNormal = []ftypes.Package{
		{ID: "pypi@2.1", Name: "pypi", Version: "2.1"},
	}

	// docker run --name poetry --rm -it python@sha256:e1141f10176d74d1a0e87a7c0a0a5a98dd98ec5ac12ce867768f40c6feae2fd9 sh
	// apk add curl
	// curl -sSL https://install.python-poetry.org | POETRY_VERSION=1.1.7 python3 -
	// export PATH=/root/.local/bin:$PATH
	// poetry new web && cd web
	// poetry add flask@1.0.3
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\"},\n") }'
	poetryFlask = []ftypes.Package{
		{ID: "click@8.1.3", Name: "click", Version: "8.1.3"},
		{ID: "colorama@0.4.6", Name: "colorama", Version: "0.4.6"},
		{ID: "flask@1.0.3", Name: "flask", Version: "1.0.3"},
		{ID: "itsdangerous@2.1.2", Name: "itsdangerous", Version: "2.1.2"},
		{ID: "jinja2@3.1.2", Name: "jinja2", Version: "3.1.2"},
		{ID: "markupsafe@2.1.2", Name: "markupsafe", Version: "2.1.2"},
		{ID: "werkzeug@2.2.3", Name: "werkzeug", Version: "2.2.3"},
	}

	// cat poetry.lock | grep "\[package.dependencies\]" -B 3 -A 8 - it might help to complete this slice
	poetryFlaskDeps = []ftypes.Dependency{
		{ID: "click@8.1.3", DependsOn: []string{"colorama@0.4.6"}},
		{ID: "flask@1.0.3", DependsOn: []string{"click@8.1.3", "itsdangerous@2.1.2", "jinja2@3.1.2", "werkzeug@2.2.3"}},
		{ID: "jinja2@3.1.2", DependsOn: []string{"markupsafe@2.1.2"}},
		{ID: "werkzeug@2.2.3", DependsOn: []string{"markupsafe@2.1.2"}},
	}

	poetryV2Flask = []ftypes.Package{
		{ID: "click@8.1.8", Name: "click", Version: "8.1.8"},
		{ID: "colorama@0.4.6", Name: "colorama", Version: "0.4.6"},
		{ID: "flask@1.0.3", Name: "flask", Version: "1.0.3"},
		{ID: "itsdangerous@2.2.0", Name: "itsdangerous", Version: "2.2.0"},
		{ID: "jinja2@3.1.5", Name: "jinja2", Version: "3.1.5"},
		{ID: "markupsafe@3.0.2", Name: "markupsafe", Version: "3.0.2"},
		{ID: "werkzeug@3.1.3", Name: "werkzeug", Version: "3.1.3"},
	}

	poetryV2FlaskDeps = []ftypes.Dependency{
		{ID: "click@8.1.8", DependsOn: []string{"colorama@0.4.6"}},
		{ID: "flask@1.0.3", DependsOn: []string{"click@8.1.8", "itsdangerous@2.2.0", "jinja2@3.1.5", "werkzeug@3.1.3"}},
		{ID: "jinja2@3.1.5", DependsOn: []string{"markupsafe@3.0.2"}},
		{ID: "werkzeug@3.1.3", DependsOn: []string{"markupsafe@3.0.2"}},
	}
)
