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
		{ID: "pytest@8.3.4", Name: "pytest", Version: "8.3.4", Relationship: ftypes.RelationshipDirect, Dev: true},
		{ID: "requests@2.32.0", Name: "requests", Version: "2.32.0", Relationship: ftypes.RelationshipDirect},
		{ID: "certifi@2024.12.14", Name: "certifi", Version: "2024.12.14", Relationship: ftypes.RelationshipIndirect},
		{ID: "charset-normalizer@3.4.0", Name: "charset-normalizer", Version: "3.4.0", Relationship: ftypes.RelationshipIndirect},
		{ID: "colorama@0.4.6", Name: "colorama", Version: "0.4.6", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "exceptiongroup@1.2.2", Name: "exceptiongroup", Version: "1.2.2", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "idna@3.10", Name: "idna", Version: "3.10", Relationship: ftypes.RelationshipIndirect},
		{ID: "iniconfig@2.0.0", Name: "iniconfig", Version: "2.0.0", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "packaging@24.2", Name: "packaging", Version: "24.2", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "pluggy@1.5.0", Name: "pluggy", Version: "1.5.0", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "tomli@2.2.1", Name: "tomli", Version: "2.2.1", Relationship: ftypes.RelationshipIndirect, Dev: true},
		{ID: "urllib3@2.2.3", Name: "urllib3", Version: "2.2.3", Relationship: ftypes.RelationshipIndirect},
	}

	// add a root project
	uvNormalDeps = []ftypes.Dependency{
		{ID: "normal@0.1.0", DependsOn: []string{"pytest@8.3.4", "requests@2.32.0"}},
		{ID: "pytest@8.3.4", DependsOn: []string{"colorama@0.4.6", "exceptiongroup@1.2.2", "iniconfig@2.0.0", "packaging@24.2", "pluggy@1.5.0", "tomli@2.2.1"}},
		{ID: "requests@2.32.0", DependsOn: []string{"certifi@2024.12.14", "charset-normalizer@3.4.0", "idna@3.10", "urllib3@2.2.3"}},
	}
)
