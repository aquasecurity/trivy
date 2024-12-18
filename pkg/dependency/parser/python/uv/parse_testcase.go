package uv

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

var (
	// docker run --name uv --rm -it python@sha256:e1141f10176d74d1a0e87a7c0a0a5a98dd98ec5ac12ce867768f40c6feae2fd9 sh
	// wget -qO- https://github.com/astral-sh/uv/releases/download/0.5.8/uv-installer.sh | sh
	// source $HOME/.local/bin/env
	// uv init normal && cd normal
	// uv add requests==2.32.0
	// apk add jq
	// uv pip list --format json |jq -c 'sort_by(.name) | .[] | {"ID": (.name + "@" + .version), "Name": .name, "Version": .version}' | sed 's/$/,/' | sed 's/\"\([^"]*\)\":/\1:/g'

	// add a root project
	// fill in the relationships between the packages
	uvNormal = []ftypes.Package{
		{ID: "normal@0.1.0", Name: "normal", Version: "0.1.0", Relationship: ftypes.RelationshipRoot},
		{ID: "requests@2.32.0", Name: "requests", Version: "2.32.0", Relationship: ftypes.RelationshipDirect},
		{ID: "certifi@2024.8.30", Name: "certifi", Version: "2024.8.30", Relationship: ftypes.RelationshipIndirect},
		{ID: "charset-normalizer@3.4.0", Name: "charset-normalizer", Version: "3.4.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "idna@3.10", Name: "idna", Version: "3.10", Relationship: ftypes.RelationshipIndirect},
		{ID: "urllib3@2.2.3", Name: "urllib3", Version: "2.2.3", Relationship: ftypes.RelationshipIndirect},
	}

	// add a root project
	uvNormalDeps = []ftypes.Dependency{
		{ID: "normal@0.1.0", DependsOn: []string{"requests@2.32.0"}},
		{ID: "requests@2.32.0", DependsOn: []string{"certifi@2024.8.30", "charset-normalizer@3.4.0", "idna@3.10", "urllib3@2.2.3"}},
	}

	// docker run --name uv --rm -it python@sha256:e1141f10176d74d1a0e87a7c0a0a5a98dd98ec5ac12ce867768f40c6feae2fd9 sh
	// wget -qO- https://github.com/astral-sh/uv/releases/download/0.5.8/uv-installer.sh | sh
	// source $HOME/.local/bin/env
	// uv init large && cd large
	// uv add asyncio==3.4.3 aiohttp==3.11.10 boto3==1.35.79 fastapi==0.115.6 simplejson==3.19.3 SQLAlchemy==2.0.36 pydantic==2.10.3 uvicorn==0.32.1
	// uv add --group dev pytest==8.3.4 ruff==0.8.2 coverage==7.6.9 codespell==2.3.0
	// uv add --group docs mkdocs==1.6.1 pymdown-extensions==10.12
	// apk add jq
	// uv pip list --format json |jq -c 'sort_by(.name) | .[] | {"ID": (.name + "@" + .version), "Name": .name, "Version": .version}' | sed 's/$/,/' | sed 's/\"\([^"]*\)\":/\1:/g'

	// add a root project
	// fill in the relationships between the packages
	uvLarge = []ftypes.Package{
		{ID: "large@0.1.0", Name: "large", Version: "0.1.0", Relationship: ftypes.RelationshipRoot},
		{ID: "aiohttp@3.11.10", Name: "aiohttp", Version: "3.11.10", Relationship: ftypes.RelationshipDirect},
		{ID: "asyncio@3.4.3", Name: "asyncio", Version: "3.4.3", Relationship: ftypes.RelationshipDirect},
		{ID: "boto3@1.35.79", Name: "boto3", Version: "1.35.79", Relationship: ftypes.RelationshipDirect},
		{ID: "fastapi@0.115.6", Name: "fastapi", Version: "0.115.6", Relationship: ftypes.RelationshipDirect},
		{ID: "pydantic@2.10.3", Name: "pydantic", Version: "2.10.3", Relationship: ftypes.RelationshipDirect},
		{ID: "simplejson@3.19.3", Name: "simplejson", Version: "3.19.3", Relationship: ftypes.RelationshipDirect},
		{ID: "sqlalchemy@2.0.36", Name: "sqlalchemy", Version: "2.0.36", Relationship: ftypes.RelationshipDirect},
		{ID: "uvicorn@0.32.1", Name: "uvicorn", Version: "0.32.1", Relationship: ftypes.RelationshipDirect},
		{ID: "aiohappyeyeballs@2.4.4", Name: "aiohappyeyeballs", Version: "2.4.4", Relationship: ftypes.RelationshipIndirect},
		{ID: "aiosignal@1.3.1", Name: "aiosignal", Version: "1.3.1", Relationship: ftypes.RelationshipIndirect},
		{ID: "annotated-types@0.7.0", Name: "annotated-types", Version: "0.7.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "anyio@4.7.0", Name: "anyio", Version: "4.7.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "async-timeout@5.0.1", Name: "async-timeout", Version: "5.0.1", Relationship: ftypes.RelationshipIndirect},
		{ID: "attrs@24.2.0", Name: "attrs", Version: "24.2.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "botocore@1.35.79", Name: "botocore", Version: "1.35.79", Relationship: ftypes.RelationshipIndirect},
		{ID: "click@8.1.7", Name: "click", Version: "8.1.7", Relationship: ftypes.RelationshipIndirect},
		{ID: "colorama@0.4.6", Name: "colorama", Version: "0.4.6", Relationship: ftypes.RelationshipIndirect},
		{ID: "exceptiongroup@1.2.2", Name: "exceptiongroup", Version: "1.2.2", Relationship: ftypes.RelationshipIndirect},
		{ID: "frozenlist@1.5.0", Name: "frozenlist", Version: "1.5.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "greenlet@3.1.1", Name: "greenlet", Version: "3.1.1", Relationship: ftypes.RelationshipIndirect},
		{ID: "h11@0.14.0", Name: "h11", Version: "0.14.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "idna@3.10", Name: "idna", Version: "3.10", Relationship: ftypes.RelationshipIndirect},
		{ID: "jmespath@1.0.1", Name: "jmespath", Version: "1.0.1", Relationship: ftypes.RelationshipIndirect},
		{ID: "multidict@6.1.0", Name: "multidict", Version: "6.1.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "propcache@0.2.1", Name: "propcache", Version: "0.2.1", Relationship: ftypes.RelationshipIndirect},
		{ID: "pydantic-core@2.27.1", Name: "pydantic-core", Version: "2.27.1", Relationship: ftypes.RelationshipIndirect},
		{ID: "python-dateutil@2.9.0.post0", Name: "python-dateutil", Version: "2.9.0.post0", Relationship: ftypes.RelationshipIndirect},
		{ID: "s3transfer@0.10.4", Name: "s3transfer", Version: "0.10.4", Relationship: ftypes.RelationshipIndirect},
		{ID: "six@1.17.0", Name: "six", Version: "1.17.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "sniffio@1.3.1", Name: "sniffio", Version: "1.3.1", Relationship: ftypes.RelationshipIndirect},
		{ID: "starlette@0.41.3", Name: "starlette", Version: "0.41.3", Relationship: ftypes.RelationshipIndirect},
		{ID: "typing-extensions@4.12.2", Name: "typing-extensions", Version: "4.12.2", Relationship: ftypes.RelationshipIndirect},
		{ID: "urllib3@1.26.20", Name: "urllib3", Version: "1.26.20", Relationship: ftypes.RelationshipIndirect},
		{ID: "yarl@1.18.3", Name: "yarl", Version: "1.18.3", Relationship: ftypes.RelationshipIndirect},
	}

	/*
		uv pip list --format json | jq -r '.[] | .name' | xargs uv pip show | awk -F ': ' '
		/^Name/ {name=$2}
		/^Version/ {version=$2}
		/^Requires/ {requires=$2}
		{
			if (requires == "") { next }
			gsub(/, /, "\", \"", requires)
			requires="[]string{\"" requires "\"}"
			print "{ID: \"" name "@" version "\", DependsOn: " requires "},"
			name=""; version=""; requires=""
		}'
	*/

	// add a root project
	// remove all groups
	uvLargeDeps = []ftypes.Dependency{
		{ID: "aiohttp@3.11.10", DependsOn: []string{"aiohappyeyeballs@2.4.4", "aiosignal@1.3.1", "async-timeout@5.0.1", "attrs@24.2.0", "frozenlist@1.5.0", "multidict@6.1.0", "propcache@0.2.1", "yarl@1.18.3"}},
		{ID: "aiosignal@1.3.1", DependsOn: []string{"frozenlist@1.5.0"}},
		{ID: "anyio@4.7.0", DependsOn: []string{"exceptiongroup@1.2.2", "idna@3.10", "sniffio@1.3.1", "typing-extensions@4.12.2"}},
		{ID: "boto3@1.35.79", DependsOn: []string{"botocore@1.35.79", "jmespath@1.0.1", "s3transfer@0.10.4"}},
		{ID: "botocore@1.35.79", DependsOn: []string{"jmespath@1.0.1", "python-dateutil@2.9.0.post0", "urllib3@1.26.20"}},
		{ID: "click@8.1.7", DependsOn: []string{"colorama@0.4.6"}},
		{ID: "fastapi@0.115.6", DependsOn: []string{"pydantic@2.10.3", "starlette@0.41.3", "typing-extensions@4.12.2"}},
		{ID: "large@0.1.0", DependsOn: []string{"aiohttp@3.11.10", "asyncio@3.4.3", "boto3@1.35.79", "fastapi@0.115.6", "pydantic@2.10.3", "simplejson@3.19.3", "sqlalchemy@2.0.36", "uvicorn@0.32.1"}},
		{ID: "multidict@6.1.0", DependsOn: []string{"typing-extensions@4.12.2"}},
		{ID: "pydantic-core@2.27.1", DependsOn: []string{"typing-extensions@4.12.2"}},
		{ID: "pydantic@2.10.3", DependsOn: []string{"annotated-types@0.7.0", "pydantic-core@2.27.1", "typing-extensions@4.12.2"}},
		{ID: "python-dateutil@2.9.0.post0", DependsOn: []string{"six@1.17.0"}},
		{ID: "s3transfer@0.10.4", DependsOn: []string{"botocore@1.35.79"}},
		{ID: "sqlalchemy@2.0.36", DependsOn: []string{"greenlet@3.1.1", "typing-extensions@4.12.2"}},
		{ID: "starlette@0.41.3", DependsOn: []string{"anyio@4.7.0", "typing-extensions@4.12.2"}},
		{ID: "uvicorn@0.32.1", DependsOn: []string{"click@8.1.7", "h11@0.14.0", "typing-extensions@4.12.2"}},
		{ID: "yarl@1.18.3", DependsOn: []string{"idna@3.10", "multidict@6.1.0", "propcache@0.2.1"}},
	}
)
