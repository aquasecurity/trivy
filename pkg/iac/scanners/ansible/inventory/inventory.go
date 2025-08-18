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
	Vars vars.Vars
}

type Group struct {
	Vars    vars.Vars
	Parents set.Set[string]
}

func (g *Group) merge(other *Group) {
	g.Vars = vars.MergeVars(g.Vars, other.Vars)
	g.Parents = g.Parents.Union(other.Parents)
}

func newGroup(vars vars.Vars, parents set.Set[string]) *Group {
	return &Group{
		Vars:    vars,
		Parents: parents,
	}
}

type Inventory struct {
	hosts      map[string]*Host
	groups     map[string]*Group
	hostGroups map[string]set.Set[string]

	externalVars vars.LoadedVars
}

func (inv *Inventory) addHost(name string, newHost *Host) {
	if inv.hosts == nil {
		inv.hosts = make(map[string]*Host)
	}

	if existing, ok := inv.hosts[name]; ok {
		// Merge Vars for existing host
		existing.Vars = vars.MergeVars(existing.Vars, newHost.Vars)
	} else {
		// Add new host
		inv.hosts[name] = &Host{
			Vars: newHost.Vars.Clone(),
		}
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

func (inv *Inventory) addHostGroups(hostName string, groups set.Set[string]) {
	if inv.hostGroups == nil {
		inv.hostGroups = make(map[string]set.Set[string])
	}

	if s, ok := inv.hostGroups[hostName]; ok {
		inv.hostGroups[hostName] = s.Union(groups)
	} else {
		inv.hostGroups[hostName] = groups.Clone()
	}
}

// ResolveVars evaluates the effective variables for the given host,
// merging values from the host itself, its groups, and parent groups,
// according to Ansible variable precedence rules.
// https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_variables.html#understanding-variable-precedence
func (inv *Inventory) ResolveVars(hostName string, playbookVars vars.LoadedVars) vars.Vars {
	effective := make(vars.Vars)

	host, ok := inv.hosts[hostName]
	if !ok {
		log.Debug("ResolveVars: host not found in inventory",
			log.String("host", hostName))
		return nil
	}

	groupsOrder, err := inv.GroupTraversalOrder(hostName)
	if err != nil {
		log.Debug("ResolveVars: failed to get group traversal order for host",
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
	mergeScopeVars(effective, inv.externalVars, vars.ScopeGroupAll, "all")
	// Resolve playbook group_vars/all
	mergeScopeVars(effective, playbookVars, vars.ScopeGroupAll, "all")
	// Resolve external group_vars/*
	mergeScopeVars(effective, inv.externalVars, vars.ScopeGroupSpecific, groupsOrder...)
	// Resolve playbook group_vars/*
	mergeScopeVars(effective, playbookVars, vars.ScopeGroupSpecific, groupsOrder...)
	// Resolve internal host vars
	maps.Copy(effective, host.Vars)
	// Resolve external host_vars/*
	mergeScopeVars(effective, inv.externalVars, vars.ScopeHost, hostName)
	// Resolve playbook host_vars/*
	mergeScopeVars(effective, playbookVars, vars.ScopeHost, hostName)
	return effective
}

func mergeScopeVars(effective vars.Vars, src vars.LoadedVars, scope vars.VarScope, keys ...string) {
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

func (inv *Inventory) GroupTraversalOrder(hostName string) ([]string, error) {
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

	hostGroups, exists := inv.hostGroups[hostName]
	if !exists {
		return nil, fmt.Errorf("host %q not found", hostName)
	}
	sortedHostGroups := hostGroups.Items()
	slices.Sort(sortedHostGroups)
	for _, name := range sortedHostGroups {
		if err := visit(name); err != nil {
			return nil, err
		}
	}

	return order, nil
}

func (inv *Inventory) initDefaultGroups() {
	if _, exists := inv.groups["all"]; !exists {
		inv.groups["all"] = newGroup(make(vars.Vars), set.New[string]())
	}

	var ungroupedHosts []string
	for hostName, groups := range inv.hostGroups {
		if groups.Size() == 0 {
			ungroupedHosts = append(ungroupedHosts, hostName)
		}
	}

	if len(ungroupedHosts) > 0 {
		if _, exists := inv.groups["ungrouped"]; !exists {
			inv.groups["ungrouped"] = newGroup(make(vars.Vars), set.New("all"))
		}
	}

	for groupName, group := range inv.groups {
		if groupName != "all" && group.Parents.Size() == 0 {
			group.Parents = set.New("all")
		}
	}
}

// ApplyVars applies a list of external variables to the inventory
func (inv *Inventory) ApplyVars(externalVars vars.LoadedVars) {
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

	// Merge hostGroups
	for host, groups := range other.hostGroups {
		inv.addHostGroups(host, groups)
	}
}
