package parser

import (
	"errors"
	"io/fs"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// Role represent project role
type Role struct {
	name     string
	roleSrc  fsutils.FileSource
	metadata iacTypes.Metadata
	play     *Play

	cachedTasks map[string][]*Task

	directDeps []*Role
}

func (r *Role) initMetadata(fsys fs.FS, parent *iacTypes.Metadata, filePath string) {
	// TODO: roles should not have metadata or
	// inherit range from role definition or include_role.
	r.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(filePath, 0, 0, "", fsys),
		"role",
	)
	r.metadata.SetParentPtr(parent)
}

func (r *Role) getTasks(tasksFile string) ([]*Task, error) {
	if cached, ok := r.cachedTasks[tasksFile]; ok {
		return cached, nil
	}

	var allTasks []*Task

	for _, dep := range r.directDeps {
		// TODO: find out how direct dependency tasks are loaded
		depTasks, err := dep.getTasks("main")
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, xerrors.Errorf("load dependency tasks from %q", dep.name)
		} else if err != nil {
			allTasks = append(allTasks, depTasks...)
		}
	}

	tasksFileSrc := r.roleSrc.Join("tasks", tasksFile)
	fileTasks, err := loadTasks(&r.metadata, tasksFileSrc)
	if err != nil {
		return nil, err
	}

	for _, roleTask := range fileTasks {
		roleTask.role = r
	}
	allTasks = append(allTasks, fileTasks...)

	r.cachedTasks[tasksFile] = allTasks
	return allTasks, nil
}

func (r *Role) fileVariables(from string) (vars.Vars, error) {
	return r.loadVars("vars", from)
}

func (r *Role) defaultVariables(from string) (vars.Vars, error) {
	return r.loadVars("defaults", from)
}

func (r *Role) loadVars(scope, from string) (vars.Vars, error) {
	var variables vars.Vars
	varsSrc := r.roleSrc.Join(scope, from)
	if err := decodeYAMLFileWithExtension(varsSrc, &variables, vars.VarFilesExtensions); err != nil {
		return nil, xerrors.Errorf("load vars from %q: %w", varsSrc.Path, err)
	}

	return variables, nil
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
