package inventory

import (
	"io/fs"
	"path"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

type LoadOptions struct {
	// InventoryPath is the path from the "inventory" config
	// in ansible.cfg.
	InventoryPath string

	// Sources are explicit inventory sources (CLI args, env vars, etc.).
	Sources []string
}

// LoadAuto resolves inventory sources from configuration, environment variables,
// and command-line flags, then loads the resulting inventory.
func LoadAuto(fsys fs.FS, opts LoadOptions) (*Inventory, error) {
	sources, err := ResolveSources(fsys, opts)
	if err != nil {
		return nil, xerrors.Errorf("resolve inventory sources: %w", err)
	}

	inv, err := LoadFromSources(fsys, sources)
	if err != nil {
		return nil, xerrors.Errorf("load from sources: %w", err)
	}

	if inv != nil {
		return inv, nil
	}

	return nil, nil
}

// LoadFromSources loads inventory files or directories from
// the given sources and merges them into a single Inventory.
func LoadFromSources(fsys fs.FS, sources []InventorySource) (*Inventory, error) {
	var inventories []*Inventory

	l := vars.VarsLoader{}

	for _, src := range sources {
		switch {
		case src.HostsFile != "":
			b, err := fs.ReadFile(fsys, src.HostsFile)
			if err != nil {
				return nil, xerrors.Errorf("read hosts file: %w", err)
			}
			inv, err := ParseYAML(b)
			if err != nil {
				return nil, xerrors.Errorf("parse hosts file: %w", err)
			}

			vars := l.Load(vars.InventoryVarsSources(fsys, src.InventoryDir))
			inv.ApplyVars(vars)
			inventories = append(inventories, inv)
		case len(src.InlineHosts) > 0:
			inventories = append(inventories, newInlineInventory(src.InlineHosts))
		case src.InventoryDir != "":
			entries, err := fs.ReadDir(fsys, src.InventoryDir)
			if err != nil {
				// TODO: log
				continue
			}

			// TODO: search for hosts_vars and group_vars in the original source directory
			vars := l.Load(vars.InventoryVarsSources(fsys, src.InventoryDir))

			for _, entry := range entries {
				b, err := fs.ReadFile(fsys, path.Join(src.InventoryDir, entry.Name()))
				if err != nil {
					// TODO: log
					continue
				}

				inv, err := ParseYAML(b)
				if err != nil {
					return nil, xerrors.Errorf("parse inventory: %w", err)
				}
				inv.ApplyVars(vars)
				inventories = append(inventories, inv)
			}
		default:
			// log unexpected source
		}
	}

	return inventories[0], nil
}

func newInlineInventory(hosts []string) *Inventory {
	return &Inventory{
		groups: map[string]*Group{
			"all": {},
			"ungrouped": {
				Parents: []string{"all"},
			},
		},
		hosts: lo.SliceToMap(hosts, func(h string) (string, *Host) {
			return h, &Host{}
		}),
		hostGroups: lo.SliceToMap(hosts, func(h string) (string, []string) {
			return h, []string{"all", "ungrouped"}
		}),
	}
}
