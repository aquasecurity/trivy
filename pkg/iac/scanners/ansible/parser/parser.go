package parser

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/inventory"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

const (
	ansibleBuiltinPrefix = "ansible.builtin."
)

func withBuiltinPrefix(actions ...string) []string {
	result := make([]string, 0, len(actions)*2)
	for _, action := range actions {
		result = append(result, action, ansibleBuiltinPrefix+action)
	}
	return result
}

type AnsibleProject struct {
	path string

	cfg       AnsibleConfig
	inventory *inventory.Inventory

	tasks []*ResolvedTask
}

func (p *AnsibleProject) Path() string {
	return p.path
}

// TODO(nikita): some tasks do not contain metadata
func (p *AnsibleProject) ListTasks() ResolvedTasks {
	return p.tasks
}

type Parser struct {
	fsys   fs.FS
	root   string
	logger *log.Logger

	// resolvedTasks caches the fully expanded list of tasks for each playbook,
	// keyed by the playbook's file path to avoid redundant parsing and resolution.
	resolvedTasks map[string][]*ResolvedTask

	// roleCache stores loaded role data keyed by role name,
	// enabling reuse of roles across multiple playbooks without repeated loading.
	roleCache map[string]*Role
}

func New(fsys fs.FS, root string) *Parser {
	return &Parser{
		fsys:   fsys,
		root:   root,
		logger: log.WithPrefix("ansible parser"),

		resolvedTasks: make(map[string][]*ResolvedTask),
		roleCache:     make(map[string]*Role),
	}
}

func ParseProject(fsys fs.FS, root string) (*AnsibleProject, error) {
	parser := New(fsys, root)
	project, err := parser.Parse()
	if err != nil {
		return nil, err
	}
	return project, nil
}

func (p *Parser) Parse(playbooks ...string) (*AnsibleProject, error) {
	project, err := p.initProject()
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

func (p *Parser) initProject() (*AnsibleProject, error) {
	cfg, err := p.readAnsibleConfig()
	if err != nil {
		return nil, xerrors.Errorf("read config: %w", err)
	}

	// TODO: pass sources
	inventory, err := inventory.LoadAuto(p.fsys, inventory.LoadOptions{
		InventoryPath: cfg.Inventory,
		Sources:       nil,
	})
	if err != nil {
		return nil, xerrors.Errorf("load inventories: %w", err)
	}

	project := &AnsibleProject{
		path:      p.root,
		cfg:       cfg,
		inventory: inventory,
	}

	return project, nil
}

func (p *Parser) parsePlaybooks(proj *AnsibleProject, paths []string) ([]*ResolvedTask, error) {
	playbooks := make(map[string]*Playbook)

	for _, filePath := range paths {
		pb, err := p.loadPlaybook(filePath)
		if err != nil {
			// Skip files that are YAML but not valid playbooks.
			p.logger.Debug("Skipping YAML file: not a playbook", log.FilePath(filePath), log.Err(err))
			continue
		}
		playbooks[filePath] = pb
	}

	entryPoints := findEntryPoints(playbooks)

	// TODO: Filter entrypoint playbooks by hosts and inventory.
	// For each play, check its 'hosts' field against the inventory (hosts and groups).
	// Include playbooks targeting at least one host from the inventory.
	// Handle special cases such as 'all', 'localhost', and dynamic variables.
	// Optionally, add a mode to bypass this filtering for full scans or debugging.

	// Resolve tasks from entrypoint playbooks — those not only imported/included by others.
	// This ensures processing of root playbooks that serve as execution starting points.
	var allTasks []*ResolvedTask
	for _, filePath := range entryPoints {
		tasks, err := p.resolvePlaybook(proj, nil, nil, filePath, playbooks)
		if err != nil {
			return nil, xerrors.Errorf("resolve playbook: %w", err)
		}
		allTasks = append(allTasks, tasks...)
	}

	return allTasks, nil
}

func (p *Parser) loadPlaybook(filePath string) (*Playbook, error) {
	var plays []*Play
	// TODO: parse templates of the following type without quotation marks: {{ public_access }}
	if err := p.decodeYAMLFile(filePath, &plays); err != nil {
		return nil, xerrors.Errorf("decode YAML file: %w", err)
	}

	return &Playbook{
		Path:  filePath,
		Plays: plays,
	}, nil
}

func findEntryPoints(playbooks map[string]*Playbook) []string {
	// TODO: use set from pkg/set
	included := set.New[string]()

	for _, pb := range playbooks {
		for _, p := range pb.Plays {
			if incPath, ok := p.includedPlaybook(); ok {
				included.Append(pb.resolveIncludedPath(incPath))
			}
		}
	}

	var entryPoints []string
	for path := range playbooks {
		if !included.Contains(path) {
			entryPoints = append(entryPoints, path)
		}
	}

	return entryPoints
}

// resolvePlaybook recursively expands tasks, roles, and included playbooks within the given playbook.
func (p *Parser) resolvePlaybook(
	proj *AnsibleProject, parent *iacTypes.Metadata, parentVars vars.Vars,
	filePath string, playbooks map[string]*Playbook,
) ([]*ResolvedTask, error) {
	pb, exists := playbooks[filePath]
	if !exists {
		// Attempt to load a playbook outside the scan directory
		var err error
		pb, err = p.loadPlaybook(filePath)
		if err != nil {
			return nil, xerrors.Errorf("load playbook: %w", err)
		}
		// Caching the loading external playbook for reuse
		playbooks[filePath] = pb
	}

	if cached, exists := p.resolvedTasks[pb.Path]; exists {
		return cached, nil
	}

	playbookInvVars := vars.LoadVars(vars.PlaybookVarsSources(p.fsys, filePath))

	var tasks []*ResolvedTask
	for _, play := range pb.Plays {

		// Initializing the metadata of the play and its nested elements
		play.initMetadata(p.fsys, parent, pb.Path)

		// TODO: resolve hosts by pattern:
		// https://docs.ansible.com/ansible/latest/inventory_guide/intro_patterns.html#common-patterns
		hosts := play.inner.Hosts

		// TODO: iterate over hosts
		hostVars := proj.inventory.ResolveVars(hosts, playbookInvVars)
		playVars := vars.MergeVars(hostVars, parentVars, play.inner.Vars)

		for _, playTask := range play.listTasks() {
			// TODO: pass parent metadata

			// TODO: Support expanding loops (e.g. 'loop', 'with_items') in tasks.
			// Example:
			// - name: Install multiple packages
			//   ansible.builtin.yum:
			//     name: "{{ item }}"
			//     state: present
			//   loop:
			//     - httpd
			//     - memcached
			//     - mariadb
			//
			// During expansion, the task should be duplicated for each item with `item` rendered.

			childrenTasks, err := p.expandTask(playVars, playTask)
			if err != nil {
				return nil, err
			}
			tasks = append(tasks, childrenTasks...)
		}

		// https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_reuse_roles.html#using-roles-at-the-play-level
		for _, roleDef := range play.roleDefinitions() {

			// When using the roles option at the play level, each role ‘x’
			// looks for files named main.yml, main.yaml, or main (without extension)
			// in its internal directories (tasks, defaults, vars, etc.).
			role, err := p.loadRole(&roleDef.metadata, play, roleDef.name())
			// Role default variables have the lowest priority
			roleVars := vars.MergeVars(
				role.defaultVariables("main"),
				playVars,
				role.fileVariables("main"),
			)
			if err != nil {
				return nil, xerrors.Errorf("load role %q: %w", roleDef.name(), err)
			}
			for _, roleTask := range role.getTasks("main") {
				childrenTasks, err := p.expandTask(roleVars, roleTask)
				if err != nil {
					return nil, err
				}
				tasks = append(tasks, childrenTasks...)
			}
		}

		// https://docs.ansible.com/ansible/latest/collections/ansible/builtin/import_playbook_module.html
		if incPath, ok := play.includedPlaybook(); ok {
			// TODO: check metadata
			fullIncPath := pb.resolveIncludedPath(incPath)
			includedTasks, err := p.resolvePlaybook(proj, &play.metadata, playVars, fullIncPath, playbooks)
			if err != nil {
				return nil, xerrors.Errorf("load playbook from %q: %w", fullIncPath, err)
			}

			tasks = append(tasks, includedTasks...)
		}
	}

	p.resolvedTasks[pb.Path] = tasks
	return tasks, nil
}

// loadRole loads a role by name.
func (p *Parser) loadRole(parent *iacTypes.Metadata, play *Play, roleName string) (*Role, error) {

	cachedRole, exists := p.roleCache[roleName]
	if exists {
		return cachedRole, nil
	}

	rolePath, exists := p.resolveRolePath(roleName)
	if !exists || rolePath == "" {
		return nil, xerrors.Errorf("role %q not found", roleName)
	}

	r := &Role{
		name:     roleName,
		play:     play,
		tasks:    make(map[string][]*Task),
		defaults: make(map[string]vars.Vars),
		vars:     make(map[string]vars.Vars),
	}
	r.initMetadata(p.fsys, parent, rolePath)

	var err error
	r.defaults, err = p.loadVarsFromDir(path.Join(rolePath, "defaults"))
	if err != nil {
		return nil, err
	}

	r.vars, err = p.loadVarsFromDir(path.Join(rolePath, "vars"))
	if err != nil {
		return nil, err
	}

	if err := p.loadRoleDependencies(r, rolePath); err != nil {
		return nil, xerrors.Errorf("load role deps: %w", err)
	}

	tasksDir := path.Join(rolePath, "tasks")
	taskFiles, err := fs.ReadDir(p.fsys, tasksDir)
	if err != nil {
		return nil, xerrors.Errorf("read tasks dir: %w", err)
	}

	for _, taskFile := range taskFiles {
		taskPath := path.Join(tasksDir, taskFile.Name())
		roleTasks, err := p.loadTasks(&r.metadata, r, taskPath)
		if err != nil {
			return nil, xerrors.Errorf("load role tasks: %w", err)
		}
		r.tasks[cutExtension(taskFile.Name())] = roleTasks
	}

	p.roleCache[roleName] = r
	return r, nil
}

// TODO: use vars package
func (p *Parser) loadVarsFromDir(dir string) (map[string]vars.Vars, error) {
	result := make(map[string]vars.Vars)

	entries, err := fs.ReadDir(p.fsys, dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return result, nil
		}
		return nil, xerrors.Errorf("read dir %q: %w", dir, err)
	}

	for _, entry := range entries {
		var variables vars.Vars
		path := path.Join(dir, entry.Name())
		if err := p.decodeYAMLFile(path, &variables); err != nil {
			return nil, xerrors.Errorf("load vars from %q: %w", path, err)
		}
		result[cutExtension(entry.Name())] = variables
	}

	return result, nil
}

func (p *Parser) loadRoleDependencies(r *Role, rolePath string) error {
	// The meta directory is an exception: it always uses the standard
	// main.yml (or main.yaml/main) file without allowing custom filenames or overrides.
	metaPath := path.Join(rolePath, "meta", "main")

	var roleMeta RoleMeta
	if err := p.decodeYAMLFileIgnoreExt(metaPath, &roleMeta); err != nil && !errors.Is(err, os.ErrNotExist) {
		return xerrors.Errorf("load meta: %w", err)
	}

	roleMeta.updateMetadata(p.fsys, &r.metadata, metaPath)

	for _, dep := range roleMeta.dependencies() {
		depRole, err := p.loadRole(&roleMeta.metadata, r.play, dep.name())
		if err != nil {
			return xerrors.Errorf("load role dependency %q: %w", dep.name(), err)
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
		if pathExists(p.fsys, rolePath) {
			return rolePath, true
		}
	}

	return "", false
}

func (p *Parser) loadTasks(parent *iacTypes.Metadata, role *Role, filePath string) ([]*Task, error) {

	var tasks []*Task
	filePath = cutExtension(filePath)
	if err := p.decodeYAMLFileIgnoreExt(filePath, &tasks); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, xerrors.Errorf("decode tasks file %q: %w", filePath, err)
	}

	var allTasks []*Task
	for _, roleTask := range tasks {
		roleTask.initMetadata(p.fsys, parent, filePath)
		roleTask.role = role
		// pass parent variables
		allTasks = append(allTasks, roleTask)
	}
	return allTasks, nil
}

// expandTask dispatches task expansion based on task type (block, include, role).
func (p *Parser) expandTask(parentVars vars.Vars, t *Task) ([]*ResolvedTask, error) {

	effectiveVars := vars.MergeVars(parentVars, t.inner.Vars)

	switch {
	case t.isBlock():
		tasks, err := p.expandBlockTasks(effectiveVars, t)
		if err != nil {
			return nil, xerrors.Errorf("expand block tasks: %w", err)
		}
		return tasks, nil
	case t.isTaskInclude():
		tasks, err := p.expandTaskInclude(effectiveVars, t)
		if err != nil {
			return nil, xerrors.Errorf("expand task include: %w", err)
		}
		return tasks, nil
	case t.isRoleInclude():
		tasks, err := p.expandRoleInclude(effectiveVars, t)
		if err != nil {
			return nil, xerrors.Errorf("expand role include: %w", err)
		}
		return tasks, nil
	default:
		resolved, err := t.resolved(effectiveVars)
		if err != nil {
			return nil, xerrors.Errorf("resolve task: %w", err)
		}
		return []*ResolvedTask{resolved}, nil
	}
}

// expandBlockTasks expands a block task into its constituent tasks.
//
// Blocks group multiple tasks under a single block in a playbook.
// See https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_blocks.html
func (p *Parser) expandBlockTasks(parentVars vars.Vars, t *Task) ([]*ResolvedTask, error) {
	var res []*ResolvedTask
	for _, task := range t.inner.Block {
		children, err := p.expandTask(parentVars, task)
		if err != nil {
			return nil, err
		}
		res = append(res, children...)
	}
	return res, nil
}

// expandTaskInclude expands tasks included or imported from external files.
//
// Supports Ansible modules 'include_tasks' and 'import_tasks'.
// See https://docs.ansible.com/ansible/latest/collections/ansible/builtin/include_tasks_module.html
func (p *Parser) expandTaskInclude(parentVars vars.Vars, task *Task) ([]*ResolvedTask, error) {
	effectiveVars := vars.MergeVars(parentVars, task.inner.Vars)
	resolvedTask, err := task.resolved(effectiveVars)
	if err != nil {
		return nil, xerrors.Errorf("resolve task: %w", err)
	}

	moduleKeys := withBuiltinPrefix(ModuleIncludeTasks, ModuleImportTasks)
	m, err := resolvedTask.ResolveModule(moduleKeys...)
	if err != nil {
		return nil, xerrors.Errorf("resolving module for keys %v: %w", moduleKeys, err)
	}

	var taskPath string
	if m.IsFreeForm() {
		taskPath = m.freeForm
	} else {
		taskPath = getStringParam(m, "file")
	}

	if taskPath == "" {
		return nil, xerrors.New("task file is empty")
	}

	// TODO: the task path can be absolute
	tasksFile := path.Join(path.Dir(task.path()), filepath.ToSlash(taskPath))
	loadedTasks, err := p.loadTasks(&task.metadata, task.role, tasksFile)
	if err != nil {
		return nil, xerrors.Errorf("load tasks from %q: %w", tasksFile, err)
	}

	var allTasks []*ResolvedTask

	for _, loadedTask := range loadedTasks {
		children, err := p.expandTask(parentVars, loadedTask)
		if err != nil {
			return nil, xerrors.Errorf("expand task: %w", err)
		}
		allTasks = append(allTasks, children...)
	}
	return allTasks, nil
}

// expandRoleInclude expands roles included or imported in the task.
//
// Supports Ansible modules 'include_role' and 'import_role'.
// See https://docs.ansible.com/ansible/latest/collections/ansible/builtin/include_role_module.html
func (p *Parser) expandRoleInclude(parentVars vars.Vars, task *Task) ([]*ResolvedTask, error) {
	effectiveVars := vars.MergeVars(parentVars, task.inner.Vars)
	resolvedTask, err := task.resolved(effectiveVars)
	if err != nil {
		return nil, xerrors.Errorf("resolve task: %w", err)
	}
	moduleKeys := withBuiltinPrefix(ModuleIncludeRole, ModuleImportRole)
	m, err := resolvedTask.ResolveModule(moduleKeys...)
	if err != nil {
		return nil, xerrors.Errorf("resolving module for keys %v: %w", moduleKeys, err)
	}

	var module RoleIncludeModule

	if m.IsFreeForm() {
		module = RoleIncludeModule{
			Name:         m.freeForm,
			TasksFrom:    "main",
			VarsFrom:     "main",
			DefaultsFrom: "main",
		}
	} else {
		module = RoleIncludeModule{
			Name:         getStringParam(m, "name"),
			TasksFrom:    cmp.Or(getStringParam(m, "tasks_from"), "main"),
			VarsFrom:     cmp.Or(getStringParam(m, "vars_from"), "main"),
			DefaultsFrom: cmp.Or(getStringParam(m, "defaults_from"), "main"),
		}
	}

	if module.Name == "" {
		return nil, xerrors.New("role name is empty")
	}

	// When using include_role/import_role, custom file names or paths can be specified
	// for various role components instead of the default "main". This applies to tasks,
	// defaults, vars, handlers, meta, etc.
	// See: https://docs.ansible.com/ansible/latest/collections/ansible/builtin/include_role_module.html
	role, err := p.loadRole(&task.metadata, task.getPlay(), module.Name)
	if err != nil {
		return nil, xerrors.Errorf("load included role %q: %w", module.Name, err)
	}

	// Role default variables have the lowest priority
	roleVars := vars.MergeVars(
		role.defaultVariables(module.DefaultsFrom),
		parentVars,
		role.fileVariables(module.VarsFrom),
	)

	var allTasks []*ResolvedTask

	for _, roleTask := range role.getTasks(module.TasksFrom) {
		// TODO: do not update the parent in the metadata here, as the dependency chain may be lost
		// if the task is a role dependency task
		// task.updateParent(t)
		children, err := p.expandTask(roleVars, roleTask)
		if err != nil {
			return nil, err
		}
		allTasks = append(allTasks, children...)
	}

	return allTasks, nil
}

func getStringParam(m Module, paramKey string) string {
	if f, exists := m.params[paramKey]; exists {
		if s, ok := f.val.(string); ok {
			return s
		}
	}
	return ""
}

func (p *Parser) decodeYAMLFileIgnoreExt(filePath string, dst any) error {
	extensions := []string{".yaml", ".yml"}

	for _, ext := range extensions {
		file := filePath + ext
		if pathExists(p.fsys, file) {
			return p.decodeYAMLFile(file, dst)
		}
	}

	return os.ErrNotExist
}

func (p *Parser) decodeYAMLFile(filePath string, dst any) error {
	data, err := fs.ReadFile(p.fsys, filePath)
	if err != nil {
		return xerrors.Errorf("read file %s: %w", filePath, err)
	}
	processedData := wrapTemplatesQuotes(string(data))
	if err := yaml.Unmarshal([]byte(processedData), dst); err != nil {
		return xerrors.Errorf("unmarshal YAML file %s: %w", filePath, err)
	}
	return nil
}

func (p *Parser) readAnsibleConfig() (AnsibleConfig, error) {
	return LoadConfig(p.fsys, p.root)
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

func pathExists(fsys fs.FS, filePath string) bool {
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

func cutExtension(filePath string) string {
	ext := filepath.Ext(filePath)
	return filePath[0 : len(filePath)-len(ext)]
}
