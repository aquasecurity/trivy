package parser

import (
	"io/fs"

	"gopkg.in/yaml.v3"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Playbook struct {
	Path  string
	Plays []*Play
	Tasks Tasks
}

func (p *Playbook) UnmarshalYAML(node *yaml.Node) error {
	return node.Decode(&p.Plays)
}

type Play struct {
	inner playInner

	metadata iacTypes.Metadata
	rng      Range

	raw map[string]any
}

type playInner struct {
	Name            string            `yaml:"name"`
	ImportPlaybook  string            `yaml:"import_playbook"`
	Hosts           string            `yaml:"hosts"`
	RoleDefinitions []*RoleDefinition `yaml:"roles"`
	PreTasks        []*Task           `yaml:"pre_tasks"`
	Tasks           []*Task           `yaml:"tasks"`
	PostTasks       []*Task           `yaml:"post_tasks"`
	Vars            Variables         `yaml:"vars"`
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

// TODO support collections
// ansible.builtin.import_playbook: my_namespace.my_collection.my_playbook
func (p *Play) isIncludePlaybook() (string, bool) {
	for _, k := range withBuiltinPrefix("import_playbook", "include_playbook") {
		val, exists := p.raw[k]
		if !exists {
			continue
		}
		// TODO: render tpl
		playbookPath, ok := val.(string)
		return playbookPath, ok
	}

	return "", false
}

func (p *Play) roleDefinitions() []*RoleDefinition {
	return p.inner.RoleDefinitions
}

func (p *Play) updateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	p.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, p.rng.startLine, p.rng.endLine, "", fsys),
		"play",
	)
	p.metadata.SetParentPtr(parent)

	for _, roleDef := range p.inner.RoleDefinitions {
		roleDef.updateMetadata(fsys, &p.metadata, path)
	}

	for _, task := range p.listTasks() {
		task.updateMetadata(fsys, &p.metadata, path)
	}
}

func (p *Play) listTasks() Tasks {
	res := make(Tasks, 0, len(p.inner.PreTasks)+len(p.inner.Tasks)+len(p.inner.PostTasks))
	res = append(res, p.inner.PreTasks...)
	res = append(res, p.inner.Tasks...)
	res = append(res, p.inner.PostTasks...)
	return res
}

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

func (r *RoleDefinition) updateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	r.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, r.rng.startLine, r.rng.endLine, "", fsys),
		"",
	)
	r.metadata.SetParentPtr(parent)
}

func (r *RoleDefinition) name() string {
	return r.inner.Name
}
