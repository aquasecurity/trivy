package parser

import (
	"cmp"
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"

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
	if err := decodeYAMLFile(p.fsys, filePath, &plays); err != nil {
		return nil, xerrors.Errorf("decode YAML file: %w", err)
	}

	return &Playbook{
		Path:  filePath,
		Plays: plays,
	}, nil
}

func findEntryPoints(playbooks map[string]*Playbook) []string {
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
		// Attempting to load a playbook outside the scan directory (may be an included playbook).
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

	// Ansible loads host and group variable files by searching paths
	// relative to the playbook file.
	// See https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html#organizing-host-and-group-variables
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

			role, err := p.loadRole(&roleDef.metadata, play, roleDef.name())
			if err != nil {
				return nil, xerrors.Errorf("load role %q: %w", roleDef.name(), err)
			}

			// Ignore non-existent files, as they are loaded by default and may be missing
			roleDefaults, err := role.defaultVariables("main")
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				log.Debug("Failed to load role default variables", log.Err(err))
			}
			roleVariables, err := role.fileVariables("main")
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				log.Debug("Failed to load role variables", log.Err(err))
			}

			// When using the roles option at the play level, each role ‘x’
			// looks for files named main.yml, main.yaml, or main (without extension)
			// in its internal directories (tasks, defaults, vars, etc.).
			roleScopeVars := vars.MergeVars(
				// Role default variables have the lowest priority
				roleDefaults,
				playVars,
				roleVariables,
			)

			// Ignore non-existent files, as they are loaded by default and may be missing
			roleTasks, err := role.getTasks("main")
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				log.Debug("Failed to load role tasks", log.Err(err))
			}

			for _, roleTask := range roleTasks {
				childrenTasks, err := p.expandTask(roleScopeVars, roleTask)
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
		name:        roleName,
		path:        rolePath,
		fsys:        p.fsys,
		play:        play,
		cachedTasks: make(map[string][]*Task),
	}
	r.initMetadata(p.fsys, parent, rolePath)

	if err := p.loadRoleDependencies(r, rolePath); err != nil {
		return nil, xerrors.Errorf("load role deps: %w", err)
	}

	p.roleCache[roleName] = r
	return r, nil
}

func (p *Parser) loadRoleDependencies(r *Role, rolePath string) error {
	// The meta directory is an exception: it always uses the standard
	// main.yml (or main.yaml/main) file without allowing custom filenames or overrides.
	metaPath := path.Join(rolePath, "meta", "main")

	var roleMeta RoleMeta
	if err := decodeYAMLFileWithExtension(p.fsys, metaPath, &roleMeta, yamlExtensions); err != nil && !errors.Is(err, os.ErrNotExist) {
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

	roleTasks, err := loadTasks(&task.metadata, p.fsys, tasksFile)
	if err != nil {
		return nil, xerrors.Errorf("load tasks from %q: %w", tasksFile, err)
	}

	var allTasks []*ResolvedTask

	for _, loadedTask := range roleTasks {
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

	roleDefaults, err := role.defaultVariables("main")
	if err != nil {
		log.Debug("Failed to load role default variables", log.Err(err))
	}
	roleVariables, err := role.fileVariables("main")
	if err != nil {
		log.Debug("Failed to load role variables", log.Err(err))
	}

	roleScopeVars := vars.MergeVars(
		// Role default variables have the lowest priority
		roleDefaults,
		parentVars,
		roleVariables,
	)

	var allTasks []*ResolvedTask

	roleTasks, err := role.getTasks(module.TasksFrom)
	if err != nil {
		return nil, xerrors.Errorf("load tasks from %q: %w", module.TasksFrom, err)
	}

	for _, roleTask := range roleTasks {
		// TODO: do not update the parent in the metadata here, as the dependency chain may be lost
		// if the task is a role dependency task
		// task.updateParent(t)
		children, err := p.expandTask(roleScopeVars, roleTask)
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

func decodeYAMLFileWithExtension(fsys fs.FS, filePath string, dst any, extensions []string) error {
	for _, ext := range extensions {
		file := filePath + ext
		if pathExists(fsys, file) {
			return decodeYAMLFile(fsys, file, dst)
		}
	}
	return os.ErrNotExist
}

func decodeYAMLFile(fsys fs.FS, filePath string, dst any) error {
	data, err := fs.ReadFile(fsys, filePath)
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

func loadTasks(parentMetadata *iacTypes.Metadata, fsys fs.FS, tasksFile string) ([]*Task, error) {
	var fileTasks []*Task
	tasksExtensions := append(yamlExtensions, "")
	if err := decodeYAMLFileWithExtension(fsys, tasksFile, &fileTasks, tasksExtensions); err != nil {
		return nil, xerrors.Errorf("decode tasks file %q: %w", tasksFile, err)
	}
	for _, roleTask := range fileTasks {
		roleTask.initMetadata(fsys, parentMetadata, tasksFile)
	}
	return fileTasks, nil
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

var yamlExtensions = []string{".yml", ".yaml"}

func isYAMLFile(filePath string) bool {
	ext := filepath.Ext(filePath)
	return slices.Contains(yamlExtensions, ext)
}
