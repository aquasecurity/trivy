package inventory

import (
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/orderedmap"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	"github.com/aquasecurity/trivy/pkg/set"
)

type rawGroup struct {
	Hosts    map[string]vars.PlainVars               `yaml:"hosts"`
	Children orderedmap.OrderedMap[string, rawGroup] `yaml:"children"`
	Vars     vars.PlainVars                          `yaml:"vars"`
}

func ParseYAML(data []byte) (*Inventory, error) {
	var raw orderedmap.OrderedMap[string, rawGroup]
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, xerrors.Errorf("unmarshal inventory yaml: %w", err)
	}

	inv := newInventory()

	for groupName, groupRaw := range raw.Iter() {
		if err := parseGroup(groupName, groupRaw, inv, nil); err != nil {
			return nil, err
		}
	}

	inv.initDefaultGroups()
	return inv, nil
}

// parseGroup recursively parses a rawGroup and adds it to Inventory
func parseGroup(name string, rg rawGroup, inv *Inventory, parents []string) error {
	// Add group
	groupVars := vars.NewVars(rg.Vars, vars.InvFileGroupPriority)
	newGroup := newGroup(groupVars, set.New(parents...))
	inv.addGroup(name, newGroup)

	// Add hosts
	// A host can be in multiple groups, but Ansible processes only one instance of the host at runtime.
	// Ansible merges the data from multiple groups.
	for hostName, plainHostVars := range rg.Hosts {
		groups := set.New(append(parents, name)...)
		// TODO: support for host ranges, e.g. www[01:50:2].example.com
		// https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html#adding-ranges-of-hosts
		hostVars := vars.NewVars(plainHostVars, vars.InvFileHostPriority)
		inv.addHost(hostName, newHost(hostVars, groups))
	}

	// Recursively parse children groups
	for childName, childRg := range rg.Children.Iter() {
		parseGroup(childName, childRg, inv, append(parents, name))
	}
	return nil
}
