package inventory

import (
	"fmt"
	"maps"
	"slices"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

type Host struct {
	Vars   vars.Vars
	Groups set.Set[string]
}

func newHost(vars vars.Vars, groups set.Set[string]) *Host {
	return &Host{Vars: vars, Groups: groups}
}

func (h *Host) merge(other *Host) {
	h.Vars = vars.MergeVars(h.Vars, other.Vars)
	h.Groups = h.Groups.Union(other.Groups)
}

type Group struct {
	Vars    vars.Vars
	Parents set.Set[string]
}

func newGroup(vars vars.Vars, parents set.Set[string]) *Group {
	return &Group{Vars: vars, Parents: parents}
}

func (g *Group) merge(other *Group) {
	g.Vars = vars.MergeVars(g.Vars, other.Vars)
	g.Parents = g.Parents.Union(other.Parents)
}

type Inventory struct {
	hosts  map[string]*Host
	groups map[string]*Group

	externalVars LoadedVars
}

func newInventory() *Inventory {
	return &Inventory{
		hosts:        make(map[string]*Host),
		groups:       make(map[string]*Group),
		externalVars: make(LoadedVars),
	}
}

func (inv *Inventory) addHost(name string, newHost *Host) {
	if inv.hosts == nil {
		inv.hosts = make(map[string]*Host)
	}

	if h, ok := inv.hosts[name]; ok {
		h.merge(newHost)
	} else {
		// Add new host
		inv.hosts[name] = newHost
	}
}

func (inv *Inventory) addGroup(name string, newGroup *Group) {
	if inv.groups == nil {
		inv.groups = make(map[string]*Group)
	}

	if g, exists := inv.groups[name]; exists {
		g.merge(newGroup)
	} else {
		inv.groups[name] = newGroup
	}
}

// ResolveVars evaluates the effective variables for the given host,
// merging values from the host itself, its groups, and parent groups,
// according to Ansible variable precedence rules.
// https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_variables.html#understanding-variable-precedence
// TODO: Add support for "ansible_group_priority"
// See https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html#how-variables-are-merged
func (inv *Inventory) ResolveVars(hostName string, playbookVars LoadedVars) vars.Vars {
	effective := make(vars.Vars)

	host, ok := inv.hosts[hostName]
	if !ok {
		log.WithPrefix("ansible").Debug("ResolveVars: host not found in inventory",
			log.String("host", hostName))
		return nil
	}

	groupsOrder, err := inv.groupTraversalOrder(hostName)
	if err != nil {
		log.WithPrefix("ansible").Debug("ResolveVars: failed to get group traversal order for host",
			log.String("host", hostName), log.Err(err))
		return nil
	}

	// Resolve internal group vars
	for _, groupName := range groupsOrder {
		if g, ok := inv.groups[groupName]; ok {
			maps.Copy(effective, g.Vars)
		}
	}

	// Resolve extenral group_vars/all
	mergeScopeVars(effective, inv.externalVars, ScopeGroupAll, "all")
	// Resolve playbook group_vars/all
	mergeScopeVars(effective, playbookVars, ScopeGroupAll, "all")
	// Resolve external group_vars/*
	mergeScopeVars(effective, inv.externalVars, ScopeGroupSpecific, groupsOrder...)
	// Resolve playbook group_vars/*
	mergeScopeVars(effective, playbookVars, ScopeGroupSpecific, groupsOrder...)
	// Resolve internal host vars
	maps.Copy(effective, host.Vars)
	// Resolve external host_vars/*
	mergeScopeVars(effective, inv.externalVars, ScopeHost, hostName)
	// Resolve playbook host_vars/*
	mergeScopeVars(effective, playbookVars, ScopeHost, hostName)
	return effective
}

func mergeScopeVars(effective vars.Vars, src LoadedVars, scope VarScope, keys ...string) {
	s, ok := src[scope]
	if !ok {
		return
	}
	for _, key := range keys {
		if v, exists := s[key]; exists {
			maps.Copy(effective, v)
		}
	}
}

func (inv *Inventory) groupTraversalOrder(hostName string) ([]string, error) {
	visited := set.New[string]()
	temp := set.New[string]()
	order := make([]string, 0, len(inv.groups))

	var visit func(string) error
	visit = func(name string) error {
		if temp.Contains(name) {
			return fmt.Errorf("cycle detected in group hierarchy at %q", name)
		}
		if visited.Contains(name) {
			return nil
		}

		temp.Append(name)
		group, ok := inv.groups[name]
		if ok {
			// // By default, Ansible merges groups at the same parent/child level in alphabetical order.
			parents := group.Parents.Items()
			slices.Sort(parents)
			for _, parent := range parents {
				if err := visit(parent); err != nil {
					return err
				}
			}
		}
		temp.Remove(name)
		visited.Append(name)
		order = append(order, name)
		return nil
	}

	host, exists := inv.hosts[hostName]
	if !exists {
		return nil, fmt.Errorf("host %q not found", hostName)
	}

	// By default, Ansible merges groups at the same parent/child level in alphabetical order.
	sortedHostGroups := host.Groups.Items()
	slices.Sort(sortedHostGroups)
	for _, name := range sortedHostGroups {
		if err := visit(name); err != nil {
			return nil, err
		}
	}

	return order, nil
}

// initDefaultGroups creates two default groups: "all" and "ungrouped".
// The "all" group contains all hosts. The "ungrouped" group contains all hosts
// that do not belong to any other group.
// See https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html#default-groups
func (inv *Inventory) initDefaultGroups() {
	allGroup := newGroup(make(vars.Vars), set.New[string]())
	inv.addGroup("all", allGroup)

	ungroupedGroup := newGroup(make(vars.Vars), set.New("all"))
	inv.addGroup("ungrouped", ungroupedGroup)

	for _, host := range inv.hosts {
		if host.Groups.Size() == 0 {
			host.Groups = set.New("ungrouped")
		}
	}

	for groupName, group := range inv.groups {
		if groupName != "all" && group.Parents.Size() == 0 {
			group.Parents = set.New("all")
		}
	}
}

// applyVars applies a list of external variables to the inventory
func (inv *Inventory) applyVars(externalVars LoadedVars) {
	inv.externalVars = externalVars
}

// Merge combines several [Inventory] into one.
func (inv *Inventory) Merge(other *Inventory) {
	// Merge hosts
	for name, h := range other.hosts {
		inv.addHost(name, h)
	}

	// Merge groups
	for name, g := range other.groups {
		inv.addGroup(name, g)
	}
}

func newInlineInventory(hosts []string) *Inventory {
	inv := &Inventory{}
	for _, hostName := range hosts {
		inv.addHost(hostName, newHost(make(vars.Vars), set.New[string]()))
	}
	inv.initDefaultGroups()
	return inv
}
