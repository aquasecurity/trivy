package parser

import (
	"io/fs"

	"gopkg.in/yaml.v3"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// Role represent project role
type Role struct {
	name     string
	metadata iacTypes.Metadata
	play     *Play

	opt LoadRoleOptions

	tasks    map[string]Tasks
	defaults Variables
	vars     Variables

	directDeps []*Role
}

func (r *Role) initMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	r.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, 0, 0, "", fsys), // TORO range
		"role",
	)
	r.metadata.SetParentPtr(parent)
}

func (r *Role) getTasks() Tasks {
	var tasks Tasks

	for _, dep := range r.directDeps {
		tasks = append(tasks, dep.getTasks()...)
	}

	tasks = append(tasks, r.tasks[r.opt.TasksFile]...)

	return tasks
}

type RoleMeta struct {
	metadata iacTypes.Metadata
	rng      Range
	inner    roleMetaInner
}

func (m *RoleMeta) updateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	m.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, m.rng.startLine, m.rng.endLine, "", fsys),
		"role-metadata",
	)
	m.metadata.SetParentPtr(parent)
}

func (m RoleMeta) dependencies() []*RoleDefinition {
	return m.inner.Dependencies
}

type roleMetaInner struct {
	Dependencies []*RoleDefinition `yaml:"dependencies"`
}

func (m *RoleMeta) UnmarshalYAML(node *yaml.Node) error {
	m.rng = rangeFromNode(node)
	return node.Decode(&m.inner)
}
