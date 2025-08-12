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

	tasks    map[string][]*Task
	defaults map[string]Vars
	vars     map[string]Vars

	directDeps []*Role
}

func (r *Role) initMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	r.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, 0, 0, "", fsys), // TORO range
		"role",
	)
	r.metadata.SetParentPtr(parent)
}

func (r *Role) getTasks(tasksFile string) []*Task {
	var allTasks []*Task

	for _, dep := range r.directDeps {
		// TODO: find out how direct dependency tasks are loaded
		allTasks = append(allTasks, dep.getTasks("main")...)
	}

	// TODO: check if the task file exists
	roleTasks, exists := r.tasks[tasksFile]
	_ = exists
	allTasks = append(allTasks, roleTasks...)
	return allTasks
}

func (r *Role) effectiveVars(defaultsFrom, varsFrom string) Vars {
	// TODO: implement variable resolution
	defaults := r.defaults[defaultsFrom]
	vars := r.vars[varsFrom]
	effectiveVars := mergeVars(defaults, vars)
	return effectiveVars
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
