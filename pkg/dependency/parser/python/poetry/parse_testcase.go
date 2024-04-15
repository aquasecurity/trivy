package poetry

import "github.com/aquasecurity/trivy/pkg/dependency/types"

var (
	// docker run --name pipenv --rm -it python@sha256:e1141f10176d74d1a0e87a7c0a0a5a98dd98ec5ac12ce867768f40c6feae2fd9 sh
	// apk add curl
	// curl -sSL https://install.python-poetry.org | python3 -
	// export PATH=/root/.local/bin:$PATH
	// poetry new normal && cd normal
	// poetry add pypi@2.1
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\"},\n") }'
	poetryNormal = []types.Library{
		{ID: "pypi@2.1", Name: "pypi", Version: "2.1"},
	}

	// docker run --name pipenv --rm -it python@sha256:e1141f10176d74d1a0e87a7c0a0a5a98dd98ec5ac12ce867768f40c6feae2fd9 sh
	// apk add curl
	// curl -sSL https://install.python-poetry.org | python3 -
	// export PATH=/root/.local/bin:$PATH
	// poetry new many && cd many
	// curl -o poetry.lock https://raw.githubusercontent.com/python-poetry/poetry/c8945eb110aeda611cc6721565d7ad0c657d453a/poetry.lock
	// curl -o pyproject.toml https://raw.githubusercontent.com/python-poetry/poetry/c8945eb110aeda611cc6721565d7ad0c657d453a/pyproject.toml
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\"},\n") }'
	// `--no-dev` flag uncorrected returns deps. Then need to remove `dev` deps manually
	// list of dev deps - cat poetry.lock | grep 'category = "dev"' -B 3
	poetryMany = []types.Library{
		{ID: "attrs@22.2.0", Name: "attrs", Version: "22.2.0"},
		{ID: "backports-cached-property@1.0.2", Name: "backports-cached-property", Version: "1.0.2"},
		{ID: "build@0.10.0", Name: "build", Version: "0.10.0"},
		{ID: "cachecontrol@0.12.11", Name: "cachecontrol", Version: "0.12.11"},
		{ID: "certifi@2022.12.7", Name: "certifi", Version: "2022.12.7"},
		{ID: "cffi@1.15.1", Name: "cffi", Version: "1.15.1"},
		{ID: "charset-normalizer@3.0.1", Name: "charset-normalizer", Version: "3.0.1"},
		{ID: "cleo@2.0.1", Name: "cleo", Version: "2.0.1"},
		{ID: "colorama@0.4.6", Name: "colorama", Version: "0.4.6"},
		{ID: "crashtest@0.4.1", Name: "crashtest", Version: "0.4.1"},
		{ID: "cryptography@39.0.0", Name: "cryptography", Version: "39.0.0"},
		{ID: "distlib@0.3.6", Name: "distlib", Version: "0.3.6"},
		{ID: "dulwich@0.21.2", Name: "dulwich", Version: "0.21.2"},
		{ID: "filelock@3.9.0", Name: "filelock", Version: "3.9.0"},
		{ID: "html5lib@1.1", Name: "html5lib", Version: "1.1"},
		{ID: "idna@3.4", Name: "idna", Version: "3.4"},
		{ID: "importlib-metadata@6.0.0", Name: "importlib-metadata", Version: "6.0.0"},
		{ID: "importlib-resources@5.10.2", Name: "importlib-resources", Version: "5.10.2"},
		{ID: "installer@0.6.0", Name: "installer", Version: "0.6.0"},
		{ID: "jaraco-classes@3.2.3", Name: "jaraco-classes", Version: "3.2.3"},
		{ID: "jeepney@0.8.0", Name: "jeepney", Version: "0.8.0"},
		{ID: "jsonschema@4.17.3", Name: "jsonschema", Version: "4.17.3"},
		{ID: "keyring@23.13.1", Name: "keyring", Version: "23.13.1"},
		{ID: "lockfile@0.12.2", Name: "lockfile", Version: "0.12.2"},
		{ID: "more-itertools@9.0.0", Name: "more-itertools", Version: "9.0.0"},
		{ID: "msgpack@1.0.4", Name: "msgpack", Version: "1.0.4"},
		{ID: "packaging@23.0", Name: "packaging", Version: "23.0"},
		{ID: "pexpect@4.8.0", Name: "pexpect", Version: "4.8.0"},
		{ID: "pkginfo@1.9.6", Name: "pkginfo", Version: "1.9.6"},
		{ID: "pkgutil-resolve-name@1.3.10", Name: "pkgutil-resolve-name", Version: "1.3.10"},
		{ID: "platformdirs@2.6.2", Name: "platformdirs", Version: "2.6.2"},
		{ID: "poetry-core@1.5.0", Name: "poetry-core", Version: "1.5.0"},
		{ID: "poetry-plugin-export@1.3.0", Name: "poetry-plugin-export", Version: "1.3.0"},
		{ID: "ptyprocess@0.7.0", Name: "ptyprocess", Version: "0.7.0"},
		{ID: "pycparser@2.21", Name: "pycparser", Version: "2.21"},
		{ID: "pyproject-hooks@1.0.0", Name: "pyproject-hooks", Version: "1.0.0"},
		{ID: "pyrsistent@0.19.3", Name: "pyrsistent", Version: "0.19.3"},
		{ID: "pywin32-ctypes@0.2.0", Name: "pywin32-ctypes", Version: "0.2.0"},
		{ID: "rapidfuzz@2.13.7", Name: "rapidfuzz", Version: "2.13.7"},
		{ID: "requests@2.28.2", Name: "requests", Version: "2.28.2"},
		{ID: "requests-toolbelt@0.10.1", Name: "requests-toolbelt", Version: "0.10.1"},
		{ID: "secretstorage@3.3.3", Name: "secretstorage", Version: "3.3.3"},
		{ID: "shellingham@1.5.0.post1", Name: "shellingham", Version: "1.5.0.post1"},
		{ID: "six@1.16.0", Name: "six", Version: "1.16.0"},
		{ID: "tomli@2.0.1", Name: "tomli", Version: "2.0.1"},
		{ID: "tomlkit@0.11.6", Name: "tomlkit", Version: "0.11.6"},
		{ID: "trove-classifiers@2023.1.20", Name: "trove-classifiers", Version: "2023.1.20"},
		{ID: "typing-extensions@4.4.0", Name: "typing-extensions", Version: "4.4.0"},
		{ID: "urllib3@1.26.14", Name: "urllib3", Version: "1.26.14"},
		{ID: "virtualenv@20.16.5", Name: "virtualenv", Version: "20.16.5"},
		{ID: "virtualenv@20.17.1", Name: "virtualenv", Version: "20.17.1"},
		{ID: "webencodings@0.5.1", Name: "webencodings", Version: "0.5.1"},
		{ID: "xattr@0.10.1", Name: "xattr", Version: "0.10.1"},
		{ID: "zipp@3.12.0", Name: "zipp", Version: "3.12.0"},
	}

	// cat poetry.lock | grep "\[package.dependencies\]" -B 3 -A 8 - it might help to complete this slice
	poetryManyDeps = []types.Dependency{
		{ID: "build@0.10.0", DependsOn: []string{"colorama@0.4.6", "importlib-metadata@6.0.0", "packaging@23.0", "pyproject-hooks@1.0.0", "tomli@2.0.1"}},
		{ID: "cachecontrol@0.12.11", DependsOn: []string{"lockfile@0.12.2", "msgpack@1.0.4", "requests@2.28.2"}},
		{ID: "cffi@1.15.1", DependsOn: []string{"pycparser@2.21"}},
		{ID: "cleo@2.0.1", DependsOn: []string{"crashtest@0.4.1", "rapidfuzz@2.13.7"}},
		{ID: "cryptography@39.0.0", DependsOn: []string{"cffi@1.15.1"}},
		{ID: "dulwich@0.21.2", DependsOn: []string{"typing-extensions@4.4.0", "urllib3@1.26.14"}},
		{ID: "html5lib@1.1", DependsOn: []string{"six@1.16.0", "webencodings@0.5.1"}},
		{ID: "importlib-metadata@6.0.0", DependsOn: []string{"typing-extensions@4.4.0", "zipp@3.12.0"}},
		{ID: "importlib-resources@5.10.2", DependsOn: []string{"zipp@3.12.0"}},
		{ID: "jaraco-classes@3.2.3", DependsOn: []string{"more-itertools@9.0.0"}},
		{ID: "jsonschema@4.17.3", DependsOn: []string{"attrs@22.2.0", "importlib-metadata@6.0.0", "importlib-resources@5.10.2", "pkgutil-resolve-name@1.3.10", "pyrsistent@0.19.3", "typing-extensions@4.4.0"}},
		{ID: "keyring@23.13.1", DependsOn: []string{"importlib-metadata@6.0.0", "importlib-resources@5.10.2", "jaraco-classes@3.2.3", "jeepney@0.8.0", "pywin32-ctypes@0.2.0", "secretstorage@3.3.3"}},
		{ID: "pexpect@4.8.0", DependsOn: []string{"ptyprocess@0.7.0"}},
		{ID: "platformdirs@2.6.2", DependsOn: []string{"typing-extensions@4.4.0"}},
		{ID: "poetry-core@1.5.0", DependsOn: []string{"importlib-metadata@6.0.0"}},
		{ID: "poetry-plugin-export@1.3.0", DependsOn: []string{"poetry-core@1.5.0"}},
		{ID: "pyproject-hooks@1.0.0", DependsOn: []string{"tomli@2.0.1"}},
		{ID: "requests@2.28.2", DependsOn: []string{"certifi@2022.12.7", "charset-normalizer@3.0.1", "idna@3.4", "urllib3@1.26.14"}},
		{ID: "requests-toolbelt@0.10.1", DependsOn: []string{"requests@2.28.2"}},
		{ID: "secretstorage@3.3.3", DependsOn: []string{"cryptography@39.0.0", "jeepney@0.8.0"}},
		{ID: "virtualenv@20.16.5", DependsOn: []string{"distlib@0.3.6", "filelock@3.9.0", "platformdirs@2.6.2"}},
		{ID: "virtualenv@20.17.1", DependsOn: []string{"distlib@0.3.6", "filelock@3.9.0", "importlib-metadata@6.0.0", "platformdirs@2.6.2"}},
		{ID: "xattr@0.10.1", DependsOn: []string{"cffi@1.15.1"}},
	}

	// docker run --name pipenv --rm -it python@sha256:e1141f10176d74d1a0e87a7c0a0a5a98dd98ec5ac12ce867768f40c6feae2fd9 sh
	// apk add curl
	// curl -sSL https://install.python-poetry.org | python3 -
	// export PATH=/root/.local/bin:$PATH
	// poetry new web && cd web
	// poetry add flask@1.0.3
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{ID: \""$1"@"$2"\", Name: \""$1"\", Version: \""$2"\"},\n") }'
	poetryFlask = []types.Library{
		{ID: "click@8.1.3", Name: "click", Version: "8.1.3"},
		{ID: "colorama@0.4.6", Name: "colorama", Version: "0.4.6"},
		{ID: "flask@1.0.3", Name: "flask", Version: "1.0.3"},
		{ID: "itsdangerous@2.1.2", Name: "itsdangerous", Version: "2.1.2"},
		{ID: "jinja2@3.1.2", Name: "jinja2", Version: "3.1.2"},
		{ID: "markupsafe@2.1.2", Name: "markupsafe", Version: "2.1.2"},
		{ID: "werkzeug@2.2.3", Name: "werkzeug", Version: "2.2.3"},
	}

	// cat poetry.lock | grep "\[package.dependencies\]" -B 3 -A 8 - it might help to complete this slice
	poetryFlaskDeps = []types.Dependency{
		{ID: "click@8.1.3", DependsOn: []string{"colorama@0.4.6"}},
		{ID: "flask@1.0.3", DependsOn: []string{"click@8.1.3", "itsdangerous@2.1.2", "jinja2@3.1.2", "werkzeug@2.2.3"}},
		{ID: "jinja2@3.1.2", DependsOn: []string{"markupsafe@2.1.2"}},
		{ID: "werkzeug@2.2.3", DependsOn: []string{"markupsafe@2.1.2"}},
	}
)
