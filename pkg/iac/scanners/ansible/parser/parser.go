package parser

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const (
	ansibleCfgFile = "ansible.cfg"

	ansibleBuiltinPrefix = "ansible.builtin."
)

func applyBuiltinPrefix(action string) string {
	return ansibleBuiltinPrefix + action
}

func withBuiltinPrefix(actions ...string) []string {
	return append(actions, lo.Map(actions, func(action string, _ int) string {
		return applyBuiltinPrefix(action)
	})...)
}

type AnsibleProject struct {
	path string

	cfg AnsibleConfig
	// inventory Inventory
	tasks Tasks
}

func (p *AnsibleProject) Path() string {
	return p.path
}

// TODO(nikita): some tasks do not contain metadata
func (p *AnsibleProject) ListTasks() Tasks {
	return p.tasks
}

type AnsibleConfig struct{}

type Parser struct {
	fsys fs.FS
	root string

	includedPlaybooks map[string]bool
	// The cache key is the path to the playbook
	playbookCache map[string]*Playbook

	// The cache key is the role name
	roleCache map[string]*Role
}

func New(fsys fs.FS, root string) *Parser {
	return &Parser{
		fsys:              fsys,
		root:              root,
		includedPlaybooks: make(map[string]bool),
		playbookCache:     make(map[string]*Playbook),
		roleCache:         make(map[string]*Role),
	}
}

func ParseProjects(fsys fs.FS, dir string) ([]*AnsibleProject, error) {
	projectPaths, err := findAnsibleProjects(fsys, dir)
	if err != nil {
		return nil, err
	}

	var projects []*AnsibleProject

	for _, projectPath := range projectPaths {
		parser := New(fsys, projectPath)
		project, err := parser.Parse()
		if err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	return projects, nil
}

func (p *Parser) Parse(playbooks ...string) (*AnsibleProject, error) {
	project, err := p.initProject(p.root)
	if err != nil {
		return nil, err
	}

	if len(playbooks) == 0 {
		playbooks, err = p.resolvePlaybooksPaths(project)
		if err != nil {
			return nil, err
		}
	}

	tasks, err := p.parsePlaybooks(project, playbooks)
	if err != nil {
		return nil, err
	}

	project.tasks = tasks
	return project, nil
}

func (p *Parser) initProject(root string) (*AnsibleProject, error) {
	cfg, err := p.readAnsibleConfig(root)
	if err != nil {
		return nil, fmt.Errorf("failed to read Ansible config: %w", err)
	}

	project := &AnsibleProject{
		path: root,
		cfg:  cfg,
	}

	return project, nil
}

func (p *Parser) parsePlaybooks(_ *AnsibleProject, paths []string) (Tasks, error) {
	mainPlaybookPath, exists := lo.Find(paths, isMainPlaybook)
	if exists {
		log.Printf("Found the main playbook %s", mainPlaybookPath) // TODO use logger
		paths = []string{mainPlaybookPath}
	}

	var playbooks []*Playbook
	for _, path := range paths {
		playbook, err := p.loadPlaybook(nil, path)
		if err != nil {
			return nil, err
		}
		playbooks = append(playbooks, playbook)
	}

	var res Tasks

	for _, playbook := range playbooks {
		// skip included playbooks to avoid duplication of tasks
		if _, exists := p.includedPlaybooks[playbook.Path]; !exists {
			res = append(res, playbook.Tasks...)
		}
	}

	return res, nil
}

func (p *Parser) loadPlaybook(parent *iacTypes.Metadata, filePath string) (*Playbook, error) {

	if cachedPlaybook, exists := p.playbookCache[filePath]; exists {
		return cachedPlaybook, nil
	}

	var playbook Playbook
	if err := p.decodeYAMLFile(filePath, &playbook); err != nil {
		// not all YAML files are playbooks.
		log.Printf("Failed to decode likely playbook %q: %s", filePath, err)
		return nil, nil
	}
	playbook.Path = filePath

	for _, play := range playbook.Plays {
		play.updateMetadata(p.fsys, parent, filePath)

		for _, playTask := range play.listTasks() {
			childrenTasks, err := p.compileTask(playTask)
			if err != nil {
				return nil, err
			}
			playbook.Tasks = append(playbook.Tasks, childrenTasks...)
		}

		for _, roleDef := range play.roleDefinitions() {
			role, err := p.loadRole(&play.metadata, play, roleDef.name())
			if err != nil {
				return nil, fmt.Errorf("failed to load role %q: %w", roleDef.name(), err)
			}
			playbook.Tasks = append(playbook.Tasks, role.getTasks()...)
		}

		// TODO: parse variables
		// https://docs.ansible.com/ansible/latest/collections/ansible/builtin/import_playbook_module.html
		if playbookPath, ok := play.isIncludePlaybook(); ok {
			// TODO: check metadata
			includedPlaybook, err := p.loadPlaybook(&play.metadata, playbookPath)
			if err != nil {
				return nil, fmt.Errorf("failed to load playbook from %q: %w", playbookPath, err)
			}
			p.includedPlaybooks[playbookPath] = true
			playbook.Tasks = append(playbook.Tasks, includedPlaybook.Tasks...)
		}
	}

	p.playbookCache[filePath] = &playbook
	return &playbook, nil
}

type LoadRoleOptions struct {
	TasksFile    string
	DefaultsFile string
	VarsFile     string
	Public       *bool
}

func (o LoadRoleOptions) withDefaults() LoadRoleOptions {
	res := LoadRoleOptions{
		TasksFile:    "main",
		DefaultsFile: "main",
		VarsFile:     "main",
		Public:       new(bool),
	}

	if o.TasksFile != "" {
		res.TasksFile = o.TasksFile
	}

	if o.DefaultsFile != "" {
		res.DefaultsFile = o.DefaultsFile
	}

	if o.VarsFile != "" {
		res.VarsFile = o.VarsFile
	}

	if o.Public != nil {
		res.Public = o.Public
	}

	return res
}

func (p *Parser) loadRole(parent *iacTypes.Metadata, play *Play, roleName string) (*Role, error) {
	return p.loadRoleWithOptions(parent, play, roleName, LoadRoleOptions{})
}

func (p *Parser) loadRoleWithOptions(parent *iacTypes.Metadata, play *Play, roleName string, opt LoadRoleOptions) (*Role, error) {

	cachedRole, exists := p.roleCache[roleName]
	if exists {
		return cachedRole, nil
	}

	rolePath, exists := p.resolveRolePath(roleName)
	if !exists {
		return nil, errors.New("role not found")
	}

	if rolePath == "" {
		return nil, fmt.Errorf("role %q not found", roleName)
	}

	r := &Role{
		name:  roleName,
		play:  play,
		opt:   opt.withDefaults(),
		tasks: make(map[string]Tasks),
	}
	r.updateMetadata(p.fsys, parent, rolePath)

	// TODO: add all defaults to role
	defaultsPath := path.Join(rolePath, "defaults", opt.DefaultsFile)
	if err := p.decodeYAMLFileIgnoreExt(defaultsPath, &r.defaults); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to load defaults: %w", err)
	}

	// TODO: add all vars to role
	varsPath := path.Join(rolePath, "vars", opt.VarsFile)
	if err := p.decodeYAMLFileIgnoreExt(varsPath, &r.vars); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to load vars: %w", err)
	}

	if err := p.loadRoleDependencies(r, rolePath); err != nil {
		return nil, fmt.Errorf("failed to load role deps: %w", err)
	}

	taskFiles, err := fs.ReadDir(p.fsys, path.Join(rolePath, "tasks"))
	if err != nil {
		return nil, err
	}

	for _, taskFile := range taskFiles {
		roleTasks, err := p.loadTasks(&r.metadata, r, path.Join(rolePath, "tasks", taskFile.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to load tasks: %w", err)
		}
		r.tasks[cutExtension(taskFile.Name())] = roleTasks
	}

	p.roleCache[roleName] = r
	return r, nil
}

func (p *Parser) loadRoleDependencies(r *Role, rolePath string) error {
	var roleMeta RoleMeta
	metaPath := path.Join(rolePath, "meta", "main")
	if err := p.decodeYAMLFileIgnoreExt(metaPath, &roleMeta); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to load meta: %w", err)
	}

	roleMeta.updateMetadata(p.fsys, &r.metadata, metaPath)

	for _, dep := range roleMeta.dependencies() {
		depRole, err := p.loadRole(&roleMeta.metadata, r.play, dep.name())
		if err != nil {
			return fmt.Errorf("failed to load dependency %q: %w", dep.name(), err)
		}
		r.directDeps = append(r.directDeps, depRole)
	}
	return nil
}

// TODO: support all possible locations of the role
// https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_reuse_roles.html
func (p *Parser) resolveRolePath(name string) (string, bool) {
	rolePaths := []string{path.Join(p.root, "roles", name)}
	if defaultRolesPath, exists := os.LookupEnv("DEFAULT_ROLES_PATH"); exists {
		// TODO: DEFAULT_ROLES_PATH can point to a directory outside of the virtual FS
		rolePaths = append(rolePaths, filepath.Join(defaultRolesPath, name))
	}

	for _, rolePath := range rolePaths {
		if isPathExists(p.fsys, rolePath) {
			return rolePath, true
		}
	}

	return "", false
}

func (p *Parser) loadTasks(parent *iacTypes.Metadata, role *Role, filePath string) (Tasks, error) {
	var roleTasks Tasks
	decode := p.decodeYAMLFile
	if path.Ext(filePath) == "" {
		decode = p.decodeYAMLFileIgnoreExt
	}
	if err := decode(filePath, &roleTasks); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("failed to decode tasks file %q: %w", filePath, err)
	}

	var tasks Tasks
	for _, roleTask := range roleTasks {
		roleTask.updateMetadata(p.fsys, parent, filePath)
		roleTask.role = role
		children, err := p.compileTask(roleTask)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, children...)
	}
	return tasks, nil
}

func (p *Parser) compileTask(t *Task) (Tasks, error) {
	switch {
	case t.isBlock():
		// https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_blocks.html
		return p.compileBlockTasks(t)
	case t.isTaskInclude():
		// https://docs.ansible.com/ansible/latest/collections/ansible/builtin/include_tasks_module.html
		// https://docs.ansible.com/ansible/latest/collections/ansible/builtin/import_tasks_module.html
		return p.compileTaskInclude(t)
	case t.isRoleInclude():
		// https://docs.ansible.com/ansible/latest/collections/ansible/builtin/include_role_module.html
		// https://docs.ansible.com/ansible/latest/collections/ansible/builtin/import_role_module.html
		return p.compileRoleInclude(t)
	default:
		// just task
		return Tasks{t}, nil
	}
}

func (p *Parser) compileBlockTasks(t *Task) (Tasks, error) {
	var res []*Task
	for _, task := range t.inner.Block {
		children, err := p.compileTask(task)
		if err != nil {
			return nil, err
		}
		res = append(res, children...)
	}
	return res, nil
}

func (p *Parser) compileTaskInclude(task *Task) (Tasks, error) {
	module, err := task.getTaskInclude()
	if err != nil {
		return nil, err
	}

	// TODO: the task path can be absolute
	tasksFile := filepath.Join(filepath.Dir(task.path()), module.File)

	loadedTasks, err := p.loadTasks(&task.metadata, task.role, tasksFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load tasks from %q: %w", tasksFile, err)
	}

	var res []*Task

	for _, loadedTask := range loadedTasks {
		children, err := p.compileTask(loadedTask)
		if err != nil {
			return nil, err
		}
		res = append(res, children...)
	}
	return res, nil
}

func (p *Parser) compileRoleInclude(task *Task) (Tasks, error) {
	module, err := task.getRoleInclude()
	if err != nil {
		return nil, err
	}

	role, err := p.loadRoleWithOptions(&task.metadata, task.getPlay(), module.Name, LoadRoleOptions{
		TasksFile:    module.TasksFrom,
		DefaultsFile: module.DefaultsFrom,
		VarsFile:     module.VarsFrom,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load role: %w", err)
	}

	var res []*Task

	for _, task := range role.getTasks() {
		// TODO: do not update the parent in the metadata here, as the dependency chain may be lost
		// if the task is a role dependency task
		// task.updateParent(t)
		children, err := p.compileTask(task)
		if err != nil {
			return nil, err
		}
		res = append(res, children...)
	}

	return res, nil
}

func (p *Parser) decodeYAMLFileIgnoreExt(filePath string, dst any) error {
	extensions := []string{".yaml", ".yml"}

	for _, ext := range extensions {
		file := filePath + ext
		if isPathExists(p.fsys, file) {
			return p.decodeYAMLFile(file, dst)
		}
	}

	return os.ErrNotExist
}

func (p *Parser) decodeYAMLFile(filePath string, dst any) error {
	f, err := p.fsys.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return yaml.NewDecoder(f).Decode(dst)
}

func (p *Parser) readAnsibleConfig(_ string) (AnsibleConfig, error) {
	// TODO(simar): Implement ansible config setup
	return AnsibleConfig{}, nil
}

func (p *Parser) resolvePlaybooksPaths(project *AnsibleProject) ([]string, error) {
	entries, err := fs.ReadDir(p.fsys, project.path)
	if err != nil {
		return nil, err
	}

	var res []string

	for _, entry := range entries {
		if isYAMLFile(entry.Name()) {
			res = append(res, filepath.Join(project.path, entry.Name()))
		}
	}

	return res, nil
}

func findAnsibleProjects(fsys fs.FS, root string) ([]string, error) {
	var res []string
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			return nil
		}

		if !isAnsibleProject(fsys, path) {
			return nil
		}
		res = append(res, path)
		return fs.SkipDir
	}

	if err := fs.WalkDir(fsys, root, walkFn); err != nil {
		return nil, err
	}

	return res, nil
}

// TODO if there are no directories listed below, then find the playbook among yaml files
func isAnsibleProject(fsys fs.FS, filePath string) bool {
	requiredDirs := []string{
		ansibleCfgFile, "site.yml", "site.yaml", "group_vars", "host_vars", "inventory", "playbooks",
	}
	for _, filename := range requiredDirs {
		if isPathExists(fsys, filepath.Join(filePath, filename)) {
			return true
		}
	}

	if entries, err := doublestar.Glob(fsys, "**/roles/**/{tasks,defaults,vars}"); err == nil && len(entries) > 0 {
		return true
	}

	if entries, err := doublestar.Glob(fsys, "*.{.yml,yaml}"); err == nil && len(entries) > 0 {
		for _, entry := range entries {
			if isPlaybook(fsys, path.Join(filePath, entry)) {
				return true
			}
		}
	}

	return false
}

func isPlaybook(fsys fs.FS, filePath string) bool {
	f, err := fsys.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	var playbook Playbook
	return yaml.NewDecoder(f).Decode(playbook) != nil
}

func isPathExists(fsys fs.FS, filePath string) bool {
	if filepath.IsAbs(filePath) {
		if _, err := os.Stat(filePath); err == nil {
			return true
		}
	}
	if _, err := fs.Stat(fsys, filePath); err == nil {
		return true
	}
	return false
}

func isYAMLFile(filePath string) bool {
	ext := filepath.Ext(filePath)
	return ext == ".yaml" || ext == ".yml"
}

func isMainPlaybook(filePath string) bool {
	return cutExtension(path.Base(filePath)) == "site"
}

func cutExtension(filePath string) string {
	ext := filepath.Ext(filePath)
	return filePath[0 : len(filePath)-len(ext)]
}
