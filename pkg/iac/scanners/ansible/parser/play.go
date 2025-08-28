package parser

import (
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/fsutils"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// Playbook represents a sequence of plays in an Ansible playbook.
//
// A playbook is typically loaded from a YAML file and contains a list
// of plays that are executed in order.
//
// The playbook corresponds to a YAML list, for example:
//
//   - name: First play
//     hosts: all
//     tasks:
//
//   - ...
//
//   - name: Second play
//     hosts: dbservers
//     tasks:
//
//   - ...
type Playbook struct {
	Src   fsutils.FileSource
	Plays []*Play
	Tasks []*Task
}

func (pb *Playbook) resolveIncludedSrc(incPath string) fsutils.FileSource {
	return pb.Src.Dir().Join(incPath)
}

// Play represents a single play in an Ansible playbook.
//
// An Ansible playbook is a list of such plays, where each play defines
// settings and tasks for a specific group of hosts.
//
// Example playbook YAML:
//
//   - name: My first play
//     hosts: myhosts
//     tasks:
//   - name: Ping my hosts
//     ping:
//
// This play contains a name, target hosts, and a list of tasks.
type Play struct {
	inner playInner

	src      fsutils.FileSource
	metadata iacTypes.Metadata
	rng      Range

	raw map[string]any
}

func (p *Play) Hosts() string {
	return p.inner.Hosts
}

func (p *Play) Variables() vars.Vars {
	return vars.NewVars(p.inner.Vars, vars.PlayVarsPriority)
}

type playInner struct {
	Name            string            `yaml:"name"`
	ImportPlaybook  string            `yaml:"import_playbook"`
	Hosts           string            `yaml:"hosts"`
	RoleDefinitions []*RoleDefinition `yaml:"roles"`
	PreTasks        []*Task           `yaml:"pre_tasks"`
	Tasks           []*Task           `yaml:"tasks"`
	PostTasks       []*Task           `yaml:"post_tasks"`
	Vars            vars.PlainVars    `yaml:"vars"`
	VarFiles        []string          `yaml:"var_files"`
}

func (p *Play) UnmarshalYAML(node *yaml.Node) error {
	p.rng = rangeFromNode(node)

	if err := node.Decode(&p.raw); err != nil {
		return err
	}

	if err := node.Decode(&p.inner); err != nil {
		return err
	}

	for _, task := range p.listTasks() {
		task.play = p
	}

	return nil
}

// includedPlaybook returns the path of an included or imported playbook within the play.
func (p *Play) includedPlaybook() (string, bool) {
	for _, k := range withBuiltinPrefix("import_playbook", "include_playbook") {
		val, exists := p.raw[k]
		if !exists {
			continue
		}

		// TODO: render Jinja2 template in playbookPath before returning
		// For example, if playbookPath == "{{ playbook_dir }}/common.yml"
		// then use a template engine to replace {{ playbook_dir }} with actual path.

		// TODO: support collections syntax like "my_namespace.my_collection.my_playbook"
		//
		// Example:
		// - name: Include a playbook from a collection
		//   ansible.builtin.import_playbook: my_namespace.my_collection.my_playbook
		//
		// convert this to a real file path by locating the collection directory
		// and appending "my_playbook.yml" or similar.

		playbookPath, ok := val.(string)
		return filepath.ToSlash(playbookPath), ok
	}

	return "", false
}

func (p *Play) roleDefinitions() []*RoleDefinition {
	return p.inner.RoleDefinitions
}

func (p *Play) initMetadata(fileSrc fsutils.FileSource, parent *iacTypes.Metadata) {
	fsys, relPath := fileSrc.FSAndRelPath()

	p.src = fileSrc
	p.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(relPath, p.rng.Start, p.rng.End, "", fsys),
		"play",
	)
	p.metadata.SetParentPtr(parent)

	for _, roleDef := range p.inner.RoleDefinitions {
		roleDef.initMetadata(fileSrc, &p.metadata)
	}

	for _, task := range p.listTasks() {
		task.init(p, fileSrc, &p.metadata)
	}
}

func (p *Play) listTasks() []*Task {
	res := make([]*Task, 0, len(p.inner.PreTasks)+len(p.inner.Tasks)+len(p.inner.PostTasks))
	res = append(res, p.inner.PreTasks...)
	res = append(res, p.inner.Tasks...)
	res = append(res, p.inner.PostTasks...)
	return res
}

// https://docs.ansible.com/ansible/latest/reference_appendices/special_variables.html
func (p *Play) specialVars() vars.Vars {
	plainVars := vars.PlainVars{
		"ansible_play_name": p.inner.Name,
		"playbook_dir":      p.src.Dir(),
	}
	return vars.NewVars(plainVars, vars.SpecialVarsPriority)
}

// RoleDefinition represents a role reference within a play.
//
// It typically contains the role name and optional parameters
// that customize how the role is applied.
//
// Example usage in a playbook:
//
//	roles:
//	  - common
//	  - role: webserver
//	    vars:
//	      http_port: 80
type RoleDefinition struct {
	inner roleDefinitionInner

	metadata iacTypes.Metadata
	rng      Range
}

type roleDefinitionInner struct {
	Name string         `yaml:"role"`
	Vars map[string]any `yaml:"vars"`
}

func (r *RoleDefinition) UnmarshalYAML(node *yaml.Node) error {
	r.rng = rangeFromNode(node)

	// a role can be a string or a dictionary
	if node.Kind == yaml.ScalarNode {
		r.inner.Name = node.Value
		return nil
	}

	return node.Decode(&r.inner)
}

func (r *RoleDefinition) initMetadata(fileSrc fsutils.FileSource, parent *iacTypes.Metadata) {
	fsys, relPath := fileSrc.FSAndRelPath()
	r.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(relPath, r.rng.Start, r.rng.End, "", fsys),
		"role-def",
	)
	r.metadata.SetParentPtr(parent)
}

func (r *RoleDefinition) name() string {
	return r.inner.Name
}
