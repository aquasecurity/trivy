package parser

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
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

type Option func(p *Parser)

func WithPlaybooks(playbooks ...string) Option {
	return func(p *Parser) {
		p.playbooks = playbooks
	}
}

func WithInventories(inventories ...string) Option {
	return func(p *Parser) {
		p.inventories = inventories
	}
}

func WithExtraVars(evars map[string]any) Option {
	return func(p *Parser) {
		p.extraVars = evars
	}
}

type Parser struct {
	fsys    fs.FS
	rootSrc fsutils.FileSource
	logger  *log.Logger

	inventories []string
	playbooks   []string
	extraVars   map[string]any

	// resolvedTasks caches the fully expanded list of tasks for each playbook,
	// keyed by the playbook's file path to avoid redundant parsing and resolution.
	resolvedTasks map[string][]*ResolvedTask

	// roleCache stores loaded role data keyed by role name,
	// enabling reuse of roles across multiple playbooks without repeated loading.
	roleCache map[string]*Role
}

func New(fsys fs.FS, root string, opts ...Option) *Parser {
	p := &Parser{
		fsys:      fsys,
		rootSrc:   fsutils.NewFileSource(fsys, root),
		logger:    log.WithPrefix("ansible"),
		extraVars: make(map[string]any),

		resolvedTasks: make(map[string][]*ResolvedTask),
		roleCache:     make(map[string]*Role),
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

func ParseProject(fsys fs.FS, root string, opts ...Option) (*AnsibleProject, error) {
	parser := New(fsys, root, opts...)
	project, err := parser.Parse()
	if err != nil {
		return nil, err
	}
	return project, nil
}

func (p *Parser) Parse() (*AnsibleProject, error) {
	p.logger.Debug("Parse Ansible project", log.FilePath(p.rootSrc.Path))
	project, err := p.initProject()
	if err != nil {
		return nil, err
	}

	playbookSources := lo.Map(p.playbooks, func(playbookPath string, _ int) fsutils.FileSource {
		return p.rootSrc.Join(playbookPath)
	})

	if len(playbookSources) == 0 {
		playbookSources, err = p.resolvePlaybooksPaths(project)
		if err != nil {
			return nil, err
		}
	}

	tasks, err := p.parsePlaybooks(project, playbookSources)
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

	inv := inventory.LoadAuto(p.fsys, inventory.LoadOptions{
		InventoryPath: cfg.Inventory,
		Sources:       p.inventories,
	})

	project := &AnsibleProject{
		path:      p.rootSrc.Path,
		cfg:       cfg,
		inventory: inv,
	}

	return project, nil
}

func (p *Parser) parsePlaybooks(proj *AnsibleProject, sources []fsutils.FileSource) ([]*ResolvedTask, error) {
	playbooks := make(map[string]*Playbook)

	for _, src := range sources {
		pb, err := p.loadPlaybook(src)
		if err != nil {
			// Skip files that are YAML but not valid playbooks.
			p.logger.Debug("Skipping YAML file: not a playbook",
				log.FilePath(src.Path), log.Err(err))
			continue
		}
		playbooks[src.Path] = pb
	}

	entryPoints := findEntryPoints(playbooks)

	// TODO: Filter entrypoint playbooks by hosts and inventory.
	// For each play, check its 'hosts' field against the inventory (hosts and groups).
	// Include playbooks targeting at least one host from the inventory.
	// Handle special cases such as 'all', 'localhost', and dynamic variables.
	// Optionally, add a mode to bypass this filtering for full scans or debugging.

	// Resolve tasks from entrypoint playbooks — those that are not imported/included by others.
	var allTasks []*ResolvedTask
	for _, playbookSrc := range entryPoints {
		tasks, err := p.resolvePlaybook(proj, nil, nil, playbookSrc, playbooks)
		if err != nil {
			return nil, xerrors.Errorf("resolve playbook: %w", err)
		}
		allTasks = append(allTasks, tasks...)
	}

	return allTasks, nil
}

func (p *Parser) loadPlaybook(f fsutils.FileSource) (*Playbook, error) {
	var plays []*Play
	if err := decodeYAMLFile(f, &plays); err != nil {
		return nil, xerrors.Errorf("decode YAML file: %w", err)
	}

	p.logger.Debug("Loaded playbook",
		log.FilePath(f.Path), log.Int("plays_count", len(plays)))
	return &Playbook{
		Src:   f,
		Plays: plays,
	}, nil
}

func findEntryPoints(playbooks map[string]*Playbook) []fsutils.FileSource {
	included := set.New[string]()

	for _, pb := range playbooks {
		for _, p := range pb.Plays {
			if incPath, ok := p.includedPlaybook(); ok {
				includedSrc := pb.resolveIncludedSrc(incPath)
				included.Append(includedSrc.Path)
			}
		}
	}

	var entryPoints []fsutils.FileSource
	for path, pb := range playbooks {
		if !included.Contains(path) {
			entryPoints = append(entryPoints, pb.Src)
		}
	}

	return entryPoints
}

// resolvePlaybook recursively expands tasks, roles, and included playbooks within the given playbook.
func (p *Parser) resolvePlaybook(
	proj *AnsibleProject, parent *iacTypes.Metadata, parentVars vars.Vars,
	playbookSrc fsutils.FileSource, playbooks map[string]*Playbook,
) ([]*ResolvedTask, error) {
	pb, exists := playbooks[playbookSrc.Path]
	if !exists {
		// Attempting to load a playbook outside the scan directory (may be an included playbook).
		var err error
		pb, err = p.loadPlaybook(playbookSrc)
		if err != nil {
			return nil, xerrors.Errorf("load playbook: %w", err)
		}
		// Caching the loading external playbook for reuse
		playbooks[playbookSrc.Path] = pb
	}

	if cached, exists := p.resolvedTasks[pb.Src.Path]; exists {
		return cached, nil
	}

	p.logger.Debug("Resolve playbook tasks", log.FilePath(pb.Src.Path))

	// Ansible loads host and group variable files by searching paths
	// relative to the playbook file.
	// See https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html#organizing-host-and-group-variables
	playbookInvVars := inventory.LoadVars(inventory.PlaybookVarsSources(playbookSrc.Dir()))

	var tasks []*ResolvedTask
	for _, play := range pb.Plays {

		// Initializing the metadata of the play and its nested elements
		play.initMetadata(playbookSrc, parent)

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
				p.logger.Debug("Failed to expand playbook task",
					log.String("source", playTask.metadata.Range().String()), log.Err(err))
			}
			tasks = append(tasks, childrenTasks...)
		}

		// https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_reuse_roles.html#using-roles-at-the-play-level
		for _, roleDef := range play.roleDefinitions() {
			roleTasks, err := p.resolveRoleDefinitionTasks(roleDef, play, playVars)
			if err != nil {
				p.logger.Debug("Failed to load role", log.String("role", roleDef.name()), log.Err(err))
				continue
			}
			tasks = append(tasks, roleTasks...)
		}

		// https://docs.ansible.com/ansible/latest/collections/ansible/builtin/import_playbook_module.html
		if incPath, ok := play.includedPlaybook(); ok {
			p.logger.Debug("Resolve playbook include",
				log.String("source", play.metadata.Range().String()),
				log.String("include", incPath),
			)

			effectiveVars := vars.MergeVars(playVars, play.specialVars())
			renderedPath, err := evaluateTemplate(incPath, effectiveVars)
			if err != nil {
				p.logger.Debug("Failed to render path",
					log.FilePath(incPath), log.Err(err))
				continue
			}

			fullIncSrc := pb.resolveIncludedSrc(renderedPath)
			includedTasks, err := p.resolvePlaybook(proj, &play.metadata, playVars, fullIncSrc, playbooks)
			if err != nil && errors.Is(err, fs.ErrNotExist) {
				p.logger.Debug("Failed to load included playbook",
					log.FilePath(fullIncSrc.Path), log.Err(err))
			} else {
				if err != nil {
					p.logger.Debug("An error occurred while resolving playbook tasks",
						log.FilePath(fullIncSrc.Path), log.Err(err))
				}
				p.logger.Debug("Loaded included playbook tasks",
					log.FilePath(fullIncSrc.Path), log.Int("tasks_count", len(includedTasks)))
				tasks = append(tasks, includedTasks...)
			}
		}
	}

	p.logger.Debug("Resolved playbook tasks",
		log.FilePath(pb.Src.Path), log.Int("tasks_count", len(tasks)))

	p.resolvedTasks[pb.Src.Path] = tasks
	return tasks, nil
}

func (p *Parser) resolveRoleDefinitionTasks(
	roleDef *RoleDefinition, play *Play, playVars vars.Vars,
) ([]*ResolvedTask, error) {
	p.logger.Debug("Resolve role at play level",
		log.String("name", roleDef.name()),
		log.String("source", roleDef.metadata.Range().String()))

	role, err := p.loadRole(&roleDef.metadata, play, roleDef.name())
	if err != nil {
		return nil, xerrors.Errorf("load role %q: %w", roleDef.name(), err)
	}

	// When using the roles option at the play level, each role ‘x’
	// looks for files named main.yml, main.yaml, or main (without extension)
	// in its internal directories (tasks, defaults, vars, etc.).

	// Ignore non-existent files, as they are loaded by default and may be missing
	roleDefaults, err := role.defaultVariables("main")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		p.logger.Debug("Failed to load role default variables", log.Err(err))
	}
	roleVariables, err := role.fileVariables("main")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		p.logger.Debug("Failed to load role variables", log.Err(err))
	}

	roleScopeVars := vars.MergeVars(
		// Role default variables have the lowest priority
		roleDefaults,
		playVars,
		roleVariables,
	)

	roleTasks, err := role.getTasks("main")
	if err != nil {
		return nil, xerrors.Errorf("load role tasks: %w", err)
	}

	var tasks []*ResolvedTask
	for _, roleTask := range roleTasks {
		childrenTasks, err := p.expandTask(roleScopeVars, roleTask)
		if err != nil {
			p.logger.Debug("Failed to expand role tasks", log.Err(err))
			continue
		}
		tasks = append(tasks, childrenTasks...)
	}

	p.logger.Debug("Included role loaded",
		log.FilePath(role.src.Path), log.Int("tasks_count", len(tasks)))
	return tasks, nil
}

// loadRole loads a role by name.
func (p *Parser) loadRole(parent *iacTypes.Metadata, play *Play, roleName string) (*Role, error) {
	cachedRole, exists := p.roleCache[roleName]
	if exists {
		return cachedRole, nil
	}

	roleSrc, exists := p.resolveRolePath(play.src.Dir(), roleName)
	if !exists || roleSrc.Path == "" {
		return nil, xerrors.Errorf("role %q not found", roleName)
	}

	r := &Role{
		name:        roleName,
		src:         roleSrc,
		play:        play,
		cachedTasks: make(map[string][]*Task),
	}
	r.initMetadata(roleSrc, parent)

	if err := p.loadRoleDependencies(r); err != nil {
		return nil, xerrors.Errorf("load role deps: %w", err)
	}

	p.roleCache[roleName] = r

	p.logger.Debug("Role found",
		log.String("name", roleName),
		log.String("source", parent.GetMetadata().Range().String()),
		log.FilePath(roleSrc.Path))
	return r, nil
}

func (p *Parser) loadRoleDependencies(r *Role) error {
	// The meta directory is an exception: it always uses the standard
	// main.yml (or main.yaml/main) file without allowing custom filenames or overrides.
	metaSrc := r.src.Join("meta", "main")

	var roleMeta RoleMeta
	if err := decodeYAMLFileWithExtension(metaSrc, &roleMeta, yamlExtensions); err != nil && !errors.Is(err, os.ErrNotExist) {
		return xerrors.Errorf("load meta: %w", err)
	}

	roleMeta.updateMetadata(metaSrc.FS, &r.metadata, metaSrc.Path)

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
func (p *Parser) resolveRolePath(playbookDirSrc fsutils.FileSource, name string) (fsutils.FileSource, bool) {

	isPath := filepath.IsAbs(name) || strings.HasPrefix(name, ".")
	if isPath {
		if !filepath.IsAbs(name) {
			// If relative path, join with playbook directory
			return playbookDirSrc.Join(name), true
		}
		return fsutils.NewFileSource(nil, name), true
	}

	roleSources := []fsutils.FileSource{
		playbookDirSrc.Join("roles", name),
	}

	if defaultRolesPath, exists := os.LookupEnv("DEFAULT_ROLES_PATH"); exists {
		rolesSrc := fsutils.NewFileSource(nil, defaultRolesPath)
		roleSources = append(roleSources, rolesSrc.Join(name))
	}

	for _, roleSrc := range roleSources {
		if exists, _ := roleSrc.Exists(); exists {
			return roleSrc, true
		}
	}

	return fsutils.FileSource{}, false
}

// expandTask dispatches task expansion based on task type (block, include, role).
func (p *Parser) expandTask(parentVars vars.Vars, t *Task) ([]*ResolvedTask, error) {

	effectiveVars := vars.MergeVars(parentVars, t.inner.Vars)

	taskSource := t.metadata.Range().String()
	switch {
	case t.isBlock():
		tasks, err := p.expandBlockTasks(effectiveVars, t)
		return wrapIfErr(tasks, fmt.Sprintf("expand block tasks %s", taskSource), err)
	case t.isTaskInclude():
		tasks, err := p.resolveTasksInclude(effectiveVars, t)
		return wrapIfErr(tasks, fmt.Sprintf("resolve tasks include %s", taskSource), err)
	case t.isRoleInclude():
		tasks, err := p.resolveRoleInclude(effectiveVars, t)
		return wrapIfErr(tasks, fmt.Sprintf("resolve role include %s", taskSource), err)
	default:
		resolvedTask := p.resolveTask(t, parentVars)
		// TODO: check that the task is not absent
		return []*ResolvedTask{resolvedTask}, nil
	}
}

// wrapIfErr adds context to err but still returns val even if err != nil.
func wrapIfErr[T any](val T, msg string, err error) (T, error) {
	if err != nil {
		return val, xerrors.Errorf("%s: %w", msg, err)
	}
	return val, nil
}

// expandBlockTasks expands a block task into its constituent tasks.
//
// Blocks group multiple tasks under a single block in a playbook.
// See https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_blocks.html
func (p *Parser) expandBlockTasks(parentVars vars.Vars, t *Task) ([]*ResolvedTask, error) {
	var res []*ResolvedTask
	var errs error
	for _, task := range t.inner.Block {
		children, err := p.expandTask(parentVars, task)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
		res = append(res, children...)
	}

	p.logger.Debug("Expanded block tasks",
		log.String("source", t.metadata.Range().String()),
		log.Int("tasks_count", len(res)),
	)
	return res, errs
}

func (p *Parser) resolveTask(task *Task, parentVars vars.Vars) *ResolvedTask {
	return task.resolved(p.effecitveVarsForTask(task, parentVars))
}

func (p *Parser) effecitveVarsForTask(task *Task, parentVars vars.Vars) vars.Vars {
	return vars.MergeVars(parentVars, task.inner.Vars, specialVarsForTask(task), p.extraVars)
}

func specialVarsForTask(task *Task) vars.Vars {
	variables := task.play.specialVars()
	if task.role != nil {
		variables = vars.MergeVars(variables, task.role.specialVars())
	}

	return variables
}

// resolveTasksInclude locates a tasks include or import file and loads its tasks.
//
// Supports Ansible modules 'include_tasks' and 'import_tasks'.
// See https://docs.ansible.com/ansible/latest/collections/ansible/builtin/include_tasks_module.html
func (p *Parser) resolveTasksInclude(parentVars vars.Vars, task *Task) ([]*ResolvedTask, error) {
	resolvedTask := p.resolveTask(task, parentVars)
	moduleKeys := withBuiltinPrefix(ModuleIncludeTasks, ModuleImportTasks)
	m, err := resolvedTask.ResolveModule(moduleKeys, true)
	if err != nil {
		return nil, xerrors.Errorf("resolving module for keys %v: %w", moduleKeys, err)
	}

	var tasksFilePath string
	if m.IsFreeForm() {
		tasksFilePath = m.freeForm
	} else {
		tasksFilePath = getStringParam(m, "file")
	}

	if tasksFilePath == "" {
		return nil, xerrors.New("tasks file is empty")
	}

	taskSrc := task.src.Dir().Join(tasksFilePath)
	includedTasks, err := loadTasks(task.play, &task.metadata, taskSrc)
	if err != nil {
		return nil, xerrors.Errorf("load tasks from %q: %w", taskSrc.Path, err)
	}

	var allTasks []*ResolvedTask

	var errs error
	for _, loadedTask := range includedTasks {
		children, err := p.expandTask(parentVars, loadedTask)
		if err != nil {
			errs = multierror.Append(xerrors.Errorf("expand included task: %w", err))
		}
		allTasks = append(allTasks, children...)
	}

	p.logger.Debug("Included tasks loaded",
		log.String("source", task.metadata.Range().String()),
		log.FilePath(taskSrc.Path),
		log.Int("tasks_count", len(allTasks)))
	return allTasks, errs
}

// resolveRoleInclude locates an included or imported role and loads its tasks.
//
// Supports Ansible modules 'include_role' and 'import_role'.
// See https://docs.ansible.com/ansible/latest/collections/ansible/builtin/include_role_module.html
func (p *Parser) resolveRoleInclude(parentVars vars.Vars, task *Task) ([]*ResolvedTask, error) {
	resolvedTask := p.resolveTask(task, parentVars)
	moduleKeys := withBuiltinPrefix(ModuleIncludeRole, ModuleImportRole)
	m, err := resolvedTask.ResolveModule(moduleKeys, true)
	if err != nil {
		return nil, xerrors.Errorf("resolving module for keys %v: %w", moduleKeys, err)
	}

	module := RoleIncludeModule{
		Name:         getStringParam(m, "name"),
		TasksFrom:    cmp.Or(getStringParam(m, "tasks_from"), "main"),
		VarsFrom:     cmp.Or(getStringParam(m, "vars_from"), "main"),
		DefaultsFrom: cmp.Or(getStringParam(m, "defaults_from"), "main"),
	}

	if module.Name == "" {
		return nil, xerrors.New("role name is empty")
	}

	// When using include_role/import_role, custom file names or paths can be specified
	// for various role components instead of the default "main". This applies to tasks,
	// defaults, vars, handlers, meta, etc.
	// See: https://docs.ansible.com/ansible/latest/collections/ansible/builtin/include_role_module.html
	role, err := p.loadRole(&task.metadata, task.play, module.Name)
	if err != nil {
		return nil, xerrors.Errorf("load included role %q: %w", module.Name, err)
	}

	roleDefaults, err := role.defaultVariables(module.DefaultsFrom)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		p.logger.Debug("Failed to load role default variables", log.Err(err))
	}
	roleVariables, err := role.fileVariables(module.VarsFrom)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		p.logger.Debug("Failed to load role variables", log.Err(err))
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

	var errs error
	for _, roleTask := range roleTasks {
		// TODO: do not update the parent in the metadata here, as the dependency chain may be lost
		// if the task is a role dependency task
		// task.updateParent(t)
		children, err := p.expandTask(roleScopeVars, roleTask)
		if err != nil {
			errs = multierror.Append(xerrors.Errorf("expand task: %w", err))
		}
		allTasks = append(allTasks, children...)
	}

	p.logger.Debug("Included role loaded",
		log.String("source", task.metadata.Range().String()),
		log.FilePath(role.src.Path),
		log.Int("tasks_count", len(allTasks)))
	return allTasks, errs
}

func getStringParam(m Module, paramKey string) string {
	if f, exists := m.params[paramKey]; exists {
		if s, ok := f.val.(string); ok {
			return s
		}
	}
	return ""
}

func decodeYAMLFileWithExtension(fileSrc fsutils.FileSource, dst any, extensions []string) error {
	for _, ext := range extensions {
		f := fsutils.FileSource{FS: fileSrc.FS, Path: fileSrc.Path + ext}
		if exists, _ := f.Exists(); exists {
			return decodeYAMLFile(f, dst)
		}
	}
	return fs.ErrNotExist
}

func decodeYAMLFile(f fsutils.FileSource, dst any) error {
	data, err := f.ReadFile()
	if err != nil {
		return xerrors.Errorf("read file %s: %w", f.Path, err)
	}
	if err := yaml.Unmarshal(data, dst); err != nil {
		return xerrors.Errorf("unmarshal YAML file %s: %w", f.Path, err)
	}
	return nil
}

func (p *Parser) readAnsibleConfig() (AnsibleConfig, error) {
	return LoadConfig(p.fsys, p.rootSrc.Path)
}

func (p *Parser) resolvePlaybooksPaths(_ *AnsibleProject) ([]fsutils.FileSource, error) {
	entries, err := p.rootSrc.ReadDir()
	if err != nil {
		return nil, err
	}

	var res []fsutils.FileSource

	for _, entry := range entries {
		if isYAMLFile(entry.Name()) {
			res = append(res, p.rootSrc.Join(entry.Name()))
		}
	}

	return res, nil
}

func loadTasks(play *Play, parentMetadata *iacTypes.Metadata, fileSrc fsutils.FileSource) ([]*Task, error) {
	var fileTasks []*Task
	tasksExtensions := append(yamlExtensions, "")
	if err := decodeYAMLFileWithExtension(fileSrc, &fileTasks, tasksExtensions); err != nil {
		return nil, xerrors.Errorf("decode tasks file %q: %w", fileSrc.Path, err)
	}
	for _, task := range fileTasks {
		task.init(play, fileSrc, parentMetadata)
	}
	return fileTasks, nil
}

var yamlExtensions = []string{".yml", ".yaml"}

func isYAMLFile(filePath string) bool {
	ext := filepath.Ext(filePath)
	return slices.Contains(yamlExtensions, ext)
}
