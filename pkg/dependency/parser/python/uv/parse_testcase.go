package uv

import ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"

var (
	// docker run --name uv --rm -it python@sha256:e1141f10176d74d1a0e87a7c0a0a5a98dd98ec5ac12ce867768f40c6feae2fd9 sh
	// wget -qO- https://github.com/astral-sh/uv/releases/download/0.5.8/uv-installer.sh | sh
	// source $HOME/.local/bin/env
	// uv init normal && cd normal
	// uv add requests==2.32.0
	// uv add --group dev pytest==8.3.4
	// apk add jq
	// uv pip list --format json |jq -c 'sort_by(.name) | .[] | {"ID": (.name + "@" + .version), "Name": .name, "Version": .version}' | sed 's/$/,/' | sed 's/\"\([^"]*\)\":/\1:/g'

	// add a root project
	// fill in the relationships between the packages
	uvNormal = []ftypes.Package{
		{ID: "normal@0.1.0", Name: "normal", Version: "0.1.0", Relationship: ftypes.RelationshipRoot},
		{ID: "requests@2.32.0", Name: "requests", Version: "2.32.0", Relationship: ftypes.RelationshipDirect},
		{ID: "certifi@2024.12.14", Name: "certifi", Version: "2024.12.14", Relationship: ftypes.RelationshipIndirect},
		{ID: "charset-normalizer@3.4.0", Name: "charset-normalizer", Version: "3.4.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "idna@3.10", Name: "idna", Version: "3.10", Relationship: ftypes.RelationshipIndirect},
		{ID: "urllib3@2.2.3", Name: "urllib3", Version: "2.2.3", Relationship: ftypes.RelationshipIndirect},
	}

	// add a root project
	uvNormalDeps = []ftypes.Dependency{
		{ID: "normal@0.1.0", DependsOn: []string{"requests@2.32.0"}},
		{ID: "requests@2.32.0", DependsOn: []string{"certifi@2024.12.14", "charset-normalizer@3.4.0", "idna@3.10", "urllib3@2.2.3"}},
	}
)
