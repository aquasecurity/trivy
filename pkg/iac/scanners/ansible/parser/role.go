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
	src      fsutils.FileSource
	metadata iacTypes.Metadata
	play     *Play

	cachedTasks map[string][]*Task

	directDeps []*Role
}

func (r *Role) initMetadata(fileSrc fsutils.FileSource, parent *iacTypes.Metadata) {
	fsys, relPath := fileSrc.FSAndRelPath()
	rng := iacTypes.NewRange(relPath, 0, 0, "", fsys)
	r.metadata = iacTypes.NewMetadata(rng, "role")
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
			log.WithPrefix("ansible").Debug("Failed to load dependency tasks",
				log.String("dependency", dep.name))
		} else if err == nil {
			allTasks = append(allTasks, depTasks...)
		}
	}

	tasksFileSrc := r.src.Join("tasks", tasksFile)
	fileTasks, err := loadTasks(r.play, &r.metadata, tasksFileSrc)
	if err != nil {
		return nil, err
	}

	for _, roleTask := range fileTasks {
		roleTask.role = r
	}
	allTasks = append(allTasks, fileTasks...)
	log.WithPrefix("ansible").Debug("Role tasks loaded",
		log.FilePath(tasksFileSrc.Path), log.Int("tasks_count", len(allTasks)))

	r.cachedTasks[tasksFile] = allTasks
	return allTasks, nil
}

func (r *Role) fileVariables(from string) (vars.Vars, error) {
	return r.loadVars("vars", vars.RoleVarsPriority, from)
}

func (r *Role) defaultVariables(from string) (vars.Vars, error) {
	return r.loadVars("defaults", vars.RoleDefaultsPriority, from)
}

func (r *Role) loadVars(scope string, priority vars.VarPriority, from string) (vars.Vars, error) {
	var variables vars.Vars

	walkFn := func(fs fsutils.FileSource, de fs.DirEntry) error {
		if de.IsDir() {
			return nil
		}

		var plainFileVars vars.PlainVars
		if err := decodeYAMLFileWithExtension(fs, &plainFileVars, vars.VarFilesExtensions); err != nil {
			return xerrors.Errorf("load vars: %w", err)
		}
		fileVars := vars.NewVars(plainFileVars, priority)
		variables = vars.MergeVars(variables, fileVars)
		return nil
	}

	varsSrc := r.src.Join(scope, from)

	// try load from file
	var plainFileVars vars.PlainVars
	if err := decodeYAMLFileWithExtension(varsSrc, &plainFileVars, vars.VarFilesExtensions); err == nil {
		log.WithPrefix("ansible").Debug("Loaded vars file", log.FilePath(varsSrc.Path))
		variables = vars.NewVars(plainFileVars, priority)
		return variables, nil
	}

	if err := fsutils.WalkDirsFirstAlpha(varsSrc, walkFn); err != nil {
		return nil, xerrors.Errorf("collect variables from %q: %w", varsSrc.Path, err)
	}

	log.WithPrefix("ansible").Debug("Loaded vars from directory",
		log.String("scope", scope), log.FilePath(varsSrc.Path))
	return variables, nil
}

// https://docs.ansible.com/ansible/latest/reference_appendices/special_variables.html
func (r *Role) specialVars() vars.Vars {
	plainVars := vars.PlainVars{
		"role_name": r.name,
		"role_path": r.src,
	}
	return vars.NewVars(plainVars, vars.SpecialVarsPriority)
}

type RoleMeta struct {
	metadata iacTypes.Metadata
	rng      Range
	inner    roleMetaInner
}

func (m *RoleMeta) updateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	m.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, m.rng.Start, m.rng.End, "", fsys),
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
