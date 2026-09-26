package uv

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

var (
	// docker run --name uv --rm -it python@sha256:e1141f10176d74d1a0e87a7c0a0a5a98dd98ec5ac12ce867768f40c6feae2fd9 sh
	// wget -qO- https://github.com/astral-sh/uv/releases/download/0.5.8/uv-installer.sh | sh
	// source $HOME/.local/bin/env
	// uv init normal && cd normal
	// uv add requests==2.32.0
	// uv add --group dev pytest==8.3.4
	// uv add httpx==0.28.1 --extra socks
	// uv add orjson==3.10.12 --optional json
	// apk add jq
	// uv pip list --format json |jq -c 'sort_by(.name) | .[] | {"ID": (.name + "@" + .version), "Name": .name, "Version": .version}' | sed 's/$/,/' | sed 's/\"\([^"]*\)\":/\1:/g'

	// add a root project
	// fill in the relationships between the packages
	uvNormal = []ftypes.Package{
		{ID: "normal@0.1.0", Name: "normal", Version: "0.1.0", Relationship: ftypes.RelationshipRoot},
		{ID: "httpx@0.28.1", Name: "httpx", Version: "0.28.1", Relationship: ftypes.RelationshipDirect},
		{ID: "orjson@3.10.12", Name: "orjson", Version: "3.10.12", Relationship: ftypes.RelationshipDirect},
		{ID: "pytest@8.3.4", Name: "pytest", Version: "8.3.4", Relationship: ftypes.RelationshipDirect, Dev: true},
		{ID: "requests@2.32.0", Name: "requests", Version: "2.32.0", Relationship: ftypes.RelationshipDirect},
		{ID: "anyio@4.7.0", Name: "anyio", Version: "4.7.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "certifi@2024.12.14", Name: "certifi", Version: "2024.12.14", Relationship: ftypes.RelationshipIndirect},
		{ID: "charset-normalizer@3.4.0", Name: "charset-normalizer", Version: "3.4.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "colorama@0.4.6", Name: "colorama", Version: "0.4.6", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "exceptiongroup@1.2.2", Name: "exceptiongroup", Version: "1.2.2", Relationship: ftypes.RelationshipIndirect},
		{ID: "h11@0.14.0", Name: "h11", Version: "0.14.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "httpcore@1.0.7", Name: "httpcore", Version: "1.0.7", Relationship: ftypes.RelationshipIndirect},
		{ID: "idna@3.10", Name: "idna", Version: "3.10", Relationship: ftypes.RelationshipIndirect},
		{ID: "iniconfig@2.0.0", Name: "iniconfig", Version: "2.0.0", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "packaging@24.2", Name: "packaging", Version: "24.2", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "pluggy@1.5.0", Name: "pluggy", Version: "1.5.0", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "sniffio@1.3.1", Name: "sniffio", Version: "1.3.1", Relationship: ftypes.RelationshipIndirect},
		{ID: "socksio@1.0.0", Name: "socksio", Version: "1.0.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "tomli@2.2.1", Name: "tomli", Version: "2.2.1", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "typing-extensions@4.12.2", Name: "typing-extensions", Version: "4.12.2", Relationship: ftypes.RelationshipIndirect},
		{ID: "urllib3@2.2.3", Name: "urllib3", Version: "2.2.3", Relationship: ftypes.RelationshipIndirect},
	}

	// add a root project
	uvNormalDeps = []ftypes.Dependency{
		{ID: "anyio@4.7.0", DependsOn: []string{"exceptiongroup@1.2.2", "idna@3.10", "sniffio@1.3.1", "typing-extensions@4.12.2"}},
		{ID: "httpcore@1.0.7", DependsOn: []string{"certifi@2024.12.14", "h11@0.14.0"}},
		{ID: "httpx@0.28.1", DependsOn: []string{"anyio@4.7.0", "certifi@2024.12.14", "httpcore@1.0.7", "idna@3.10", "socksio@1.0.0"}},
		{ID: "normal@0.1.0", DependsOn: []string{"httpx@0.28.1", "orjson@3.10.12", "pytest@8.3.4", "requests@2.32.0"}},
		{ID: "pytest@8.3.4", DependsOn: []string{"colorama@0.4.6", "exceptiongroup@1.2.2", "iniconfig@2.0.0", "packaging@24.2", "pluggy@1.5.0", "tomli@2.2.1"}},
		{ID: "requests@2.32.0", DependsOn: []string{"certifi@2024.12.14", "charset-normalizer@3.4.0", "idna@3.10", "urllib3@2.2.3"}},
	}

	// uv 0.10.12
	// pyproject.toml of the "forkdemo" project, locked with `uv lock`:
	//   requires-python = ">=3.9"
	//   dependencies = [
	//     "numpy>=1.24,<2; python_version < '3.10'",
	//     "numpy>=2.1; python_version >= '3.10'",
	//     "pandas>=2.0",
	//   ]
	//   [dependency-groups]
	//   dev = ["pytest>=8"]
	// The resolution forks by Python version, so numpy, pandas, pytest and iniconfig are locked
	// in several versions. pytz is only required by pandas 2.3.3, which is a production dependency.
	// sdist and wheels entries are removed from the lock file.
	uvMultipleVersions = []ftypes.Package{
		{ID: "forkdemo@0.1.0", Name: "forkdemo", Version: "0.1.0", Relationship: ftypes.RelationshipRoot},
		{ID: "numpy@1.26.4", Name: "numpy", Version: "1.26.4", Relationship: ftypes.RelationshipDirect},
		{ID: "numpy@2.2.6", Name: "numpy", Version: "2.2.6", Relationship: ftypes.RelationshipDirect},
		{ID: "numpy@2.4.6", Name: "numpy", Version: "2.4.6", Relationship: ftypes.RelationshipDirect},
		{ID: "numpy@2.5.3", Name: "numpy", Version: "2.5.3", Relationship: ftypes.RelationshipDirect},
		{ID: "pandas@2.3.3", Name: "pandas", Version: "2.3.3", Relationship: ftypes.RelationshipDirect},
		{ID: "pandas@3.0.6", Name: "pandas", Version: "3.0.6", Relationship: ftypes.RelationshipDirect},
		{ID: "pytest@8.4.2", Name: "pytest", Version: "8.4.2", Relationship: ftypes.RelationshipDirect, Dev: true},
		{ID: "pytest@9.1.1", Name: "pytest", Version: "9.1.1", Relationship: ftypes.RelationshipDirect, Dev: true},
		{ID: "colorama@0.4.6", Name: "colorama", Version: "0.4.6", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "exceptiongroup@1.3.1", Name: "exceptiongroup", Version: "1.3.1", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "iniconfig@2.1.0", Name: "iniconfig", Version: "2.1.0", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "iniconfig@2.3.0", Name: "iniconfig", Version: "2.3.0", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "packaging@26.3", Name: "packaging", Version: "26.3", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "pluggy@1.6.0", Name: "pluggy", Version: "1.6.0", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "pygments@2.21.0", Name: "pygments", Version: "2.21.0", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "python-dateutil@2.9.0.post0", Name: "python-dateutil", Version: "2.9.0.post0", Relationship: ftypes.RelationshipIndirect},
		{ID: "pytz@2026.4", Name: "pytz", Version: "2026.4", Relationship: ftypes.RelationshipIndirect},
		{ID: "six@1.17.0", Name: "six", Version: "1.17.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "tomli@2.4.1", Name: "tomli", Version: "2.4.1", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "typing-extensions@4.16.0", Name: "typing-extensions", Version: "4.16.0", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "tzdata@2026.4", Name: "tzdata", Version: "2026.4", Relationship: ftypes.RelationshipIndirect},
	}

	uvMultipleVersionsDeps = []ftypes.Dependency{
		{ID: "exceptiongroup@1.3.1", DependsOn: []string{"typing-extensions@4.16.0"}},
		{ID: "forkdemo@0.1.0", DependsOn: []string{"numpy@1.26.4", "numpy@2.2.6", "numpy@2.4.6", "numpy@2.5.3", "pandas@2.3.3", "pandas@3.0.6", "pytest@8.4.2", "pytest@9.1.1"}},
		{ID: "pandas@2.3.3", DependsOn: []string{"numpy@1.26.4", "numpy@2.2.6", "python-dateutil@2.9.0.post0", "pytz@2026.4", "tzdata@2026.4"}},
		{ID: "pandas@3.0.6", DependsOn: []string{"numpy@2.4.6", "numpy@2.5.3", "python-dateutil@2.9.0.post0", "tzdata@2026.4"}},
		{ID: "pytest@8.4.2", DependsOn: []string{"colorama@0.4.6", "exceptiongroup@1.3.1", "iniconfig@2.1.0", "packaging@26.3", "pluggy@1.6.0", "pygments@2.21.0", "tomli@2.4.1"}},
		{ID: "pytest@9.1.1", DependsOn: []string{"colorama@0.4.6", "exceptiongroup@1.3.1", "iniconfig@2.3.0", "packaging@26.3", "pluggy@1.6.0", "pygments@2.21.0", "tomli@2.4.1"}},
		{ID: "python-dateutil@2.9.0.post0", DependsOn: []string{"six@1.17.0"}},
	}
)
