package inventory

import (
	"fmt"
	"maps"
	"slices"

	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

type Host struct {
	Vars vars.Vars
}

type Group struct {
	Vars     vars.Vars
	Children []string

	Parents []string
}

type Inventory struct {
	hosts      map[string]*Host
	groups     map[string]*Group
	hostGroups map[string][]string

	externalVars      map[vars.VarScope][]vars.LoadedVars
	externalGroupVars map[string]vars.Vars
}

// ResolveVars evaluates the effective variables for the given host,
// merging values from the host itself, its groups, and parent groups,
// according to Ansible variable precedence rules.
// https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_variables.html#understanding-variable-precedence
func (inv *Inventory) ResolveVars(hostName string) vars.Vars {
	effective := make(vars.Vars)

	host, ok := inv.hosts[hostName]
	if !ok {
		// TODO: log missing host
		return nil
	}

	order, err := inv.GroupTraversalOrder(hostName)
	if err != nil {
		// TODO: log or return error
		return nil
	}

	// Resolve internal group vars
	for _, groupName := range order {
		if g, ok := inv.groups[groupName]; ok {
			maps.Copy(effective, g.Vars)
		}
	}

	// Resolve extenral group_vars/all
	for _, external := range inv.externalVars[vars.ScopeGroupAll] {
		maps.Copy(effective, external.Vars)
	}

	// Resolve external group_vars/*
	for _, groupName := range order {
		maps.Copy(effective, inv.externalGroupVars[groupName])
	}

	// Resolve internal host vars
	maps.Copy(effective, host.Vars)

	// Resolve host_vars/*
	for _, external := range inv.externalVars[vars.ScopeHost] {
		if external.Target == hostName {
			maps.Copy(effective, external.Vars)
		}
	}

	return effective
}

func (inv *Inventory) GroupTraversalOrder(hostName string) ([]string, error) {
	visited := make(map[string]bool)
	temp := make(map[string]bool)
	order := make([]string, 0, len(inv.groups))

	var visit func(string) error
	visit = func(name string) error {
		if temp[name] {
			return fmt.Errorf("cycle detected in group hierarchy at %q", name)
		}
		if visited[name] {
			return nil
		}

		temp[name] = true
		group, ok := inv.groups[name]
		if ok {
			sortedParents := slices.Clone(group.Parents)
			slices.Sort(sortedParents)
			for _, parent := range sortedParents {
				if err := visit(parent); err != nil {
					return err
				}
			}
		}
		temp[name] = false
		visited[name] = true
		order = append(order, name)
		return nil
	}

	hostGroups, exists := inv.hostGroups[hostName]
	if !exists {
		// TODO: log missing host
		return nil, nil
	}
	sortedHostGroups := slices.Clone(hostGroups)
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
		inv.groups["all"] = &Group{}
	}

	var ungroupedHosts []string
	for hostName, groups := range inv.hostGroups {
		if len(groups) == 0 {
			ungroupedHosts = append(ungroupedHosts, hostName)
		}
	}

	if len(ungroupedHosts) > 0 {
		if _, exists := inv.groups["ungrouped"]; !exists {
			inv.groups["ungrouped"] = &Group{}
		}
	}

	for groupName, group := range inv.groups {
		if groupName != "all" && len(group.Parents) == 0 {
			group.Parents = []string{"all"}
		}
	}
}

// ApplyVars applies a list of external variables to the inventory
func (inv *Inventory) ApplyVars(externalVars []vars.LoadedVars) {
	inv.externalVars = lo.GroupBy(externalVars, func(v vars.LoadedVars) vars.VarScope {
		return v.Scope
	})

	inv.externalGroupVars = make(map[string]vars.Vars)
	for _, external := range inv.externalVars[vars.ScopeGroupSpecific] {
		groupVars := inv.externalGroupVars[external.Target]
		inv.externalGroupVars[external.Target] = vars.MergeVars(groupVars, external.Vars)
	}
}

// Merge combines several [Inventory] into one.
// Merges groups, hosts, and priority variables.
func Merge(_ ...*Inventory) *Inventory {
	// TODO: implement
	return nil
}
