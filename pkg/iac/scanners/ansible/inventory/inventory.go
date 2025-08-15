package inventory

import (
	"fmt"
	"maps"
	"slices"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
	"github.com/aquasecurity/trivy/pkg/log"
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

	externalVars vars.LoadedVars
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
func (inv *Inventory) ApplyVars(externalVars vars.LoadedVars) {
	inv.externalVars = externalVars
}

// Merge combines several [Inventory] into one.
func (inv *Inventory) Merge(other *Inventory) {
	if inv.hosts == nil {
		inv.hosts = make(map[string]*Host)
	}
	if inv.groups == nil {
		inv.groups = make(map[string]*Group)
	}
	if inv.hostGroups == nil {
		inv.hostGroups = make(map[string][]string)
	}

	// Merge hosts
	for name, h := range other.hosts {
		if existing, ok := inv.hosts[name]; ok {
			// Merge Vars for existing host
			inv.hosts[name].Vars = vars.MergeVars(existing.Vars, h.Vars)
		} else {
			// Add new host
			inv.hosts[name] = &Host{
				Vars: h.Vars.Clone(),
			}
		}
	}

	// Merge groups
	for name, g := range other.groups {
		if existing, ok := inv.groups[name]; ok {
			// Merge Vars
			existing.Vars = vars.MergeVars(existing.Vars, g.Vars)

			// Merge Children and Parents without duplicates
			existing.Children = mergeStringSlices(existing.Children, g.Children)
			existing.Parents = mergeStringSlices(existing.Parents, g.Parents)
		} else {
			// Add new group
			inv.groups[name] = &Group{
				Vars:     g.Vars.Clone(),
				Children: append([]string(nil), g.Children...),
				Parents:  append([]string(nil), g.Parents...),
			}
		}
	}

	// Merge hostGroups
	for host, groups := range other.hostGroups {
		inv.hostGroups[host] = mergeStringSlices(inv.hostGroups[host], groups)
	}
}

// mergeStringSlices merges two slices of strings without duplicates.
func mergeStringSlices(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	var result []string

	for _, s := range a {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	for _, s := range b {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			result = append(result, s)
		}
	}
	return result
}
