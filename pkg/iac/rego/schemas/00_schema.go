package schemas

import _ "embed"

type Schema string

var (
	None     Schema = ""
	Anything Schema = `{}`

	//go:embed dockerfile.json
	Dockerfile Schema

	//go:embed kubernetes.json
	Kubernetes Schema

	//go:embed rbac.json
	RBAC Schema

	//go:embed cloud.json
	Cloud Schema
)
