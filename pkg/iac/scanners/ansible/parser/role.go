package parser

import (
	"errors"
	"io/fs"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
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
			log.Debug("Failed to load dependency tasks", log.String("dependency", dep.name))
		} else if err == nil {
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
	log.Debug("Role tasks loaded", log.FilePath(tasksFileSrc.Path))

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

	walkFn := func(fs fsutils.FileSource, de fs.DirEntry) error {
		if de.IsDir() {
			return nil
		}

		var fileVars vars.Vars
		if err := decodeYAMLFileWithExtension(fs, &fileVars, vars.VarFilesExtensions); err != nil {
			return xerrors.Errorf("load vars: %w", err)
		}
		variables = vars.MergeVars(variables, fileVars)
		return nil
	}

	varsSrc := r.roleSrc.Join(scope, from)

	// try load from file
	if err := decodeYAMLFileWithExtension(varsSrc, &variables, vars.VarFilesExtensions); err == nil {
		log.Debug("Loaded vars file", log.FilePath(varsSrc.Path))
		return variables, nil
	}

	if err := fsutils.WalkDirsFirstAlpha(varsSrc, walkFn); err != nil {
		return nil, xerrors.Errorf("collect variables from %q: %w", varsSrc.Path, err)
	}

	log.Debug("Loaded vars from directory", log.FilePath(varsSrc.Path))
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
