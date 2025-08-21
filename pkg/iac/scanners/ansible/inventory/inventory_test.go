package inventory_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/inventory"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

func TestInventory_ResolveVars_YAML(t *testing.T) {
	src := `
all:
  vars:
    location: dc1
    os: linux

leafs1:
  vars:
    os: eos
    role: leaf
  hosts:
    leaf01:
      role: custom-leaf2
      tag: leafs1
    leaf02:
      ansible_host: 192.0.2.110

leafs0:
  vars:
    os: nxos
  hosts:
    leaf01:
      ansible_host: 192.0.2.100
      role: custom-leaf

spines:
  vars:
    role: spine
  hosts:
    spine01:
      ansible_host: 192.0.2.120
    spine02:
      ansible_host: 192.0.2.130
      os: nxos

network0:
  vars:
    environment: dev
  children:
    leafs0:
    leafs1:
    spines:

network1:
  vars:
    environment: prod
  children:
    network0:
    leafs1:
    spines:

webservers:
  vars:
    role: web
  hosts:
    webserver01:
      ansible_host: 192.0.2.140
    webserver02:
      ansible_host: 192.0.2.150

datacenter:
  children:
    network0:
    network1:
    webservers:
`

	inv, err := inventory.ParseYAML([]byte(src))
	require.NoError(t, err)

	tests := []struct {
		hostName string
		expected vars.Vars
	}{
		{
			hostName: "leaf01",
			expected: vars.Vars{
				"location":     "dc1",         // from all
				"tag":          "leafs1",      // from leafs1
				"os":           "eos",         // from leafs1
				"role":         "custom-leaf", // overridden at host
				"environment":  "dev",         // from network1
				"ansible_host": "192.0.2.100", // from host
			},
		},
		{
			hostName: "leaf02",
			expected: vars.Vars{
				"location":     "dc1",
				"os":           "eos",  // from leafs1
				"role":         "leaf", // from leafs1
				"environment":  "dev",  // from network1
				"ansible_host": "192.0.2.110",
			},
		},
		{
			hostName: "spine01",
			expected: vars.Vars{
				"location":     "dc1",
				"os":           "linux", // from all
				"role":         "spine", // from spines
				"environment":  "dev",
				"ansible_host": "192.0.2.120",
			},
		},
		{
			hostName: "spine02",
			expected: vars.Vars{
				"location":     "dc1",
				"os":           "nxos", // overridden at host
				"role":         "spine",
				"environment":  "dev",
				"ansible_host": "192.0.2.130",
			},
		},
		{
			hostName: "webserver01",
			expected: vars.Vars{
				"location":     "dc1",
				"os":           "linux",
				"role":         "web",
				"ansible_host": "192.0.2.140",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.hostName, func(t *testing.T) {
			got := inv.ResolveVars(tt.hostName, make(vars.LoadedVars))
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestInventory_ResolveVars_INI(t *testing.T) {

	src := `
ungrouped1 ansible_host=10.0.0.99 description="standalone;# \"host"

[ungrouped:vars]
# comment
; comment
http_port=8080

[all:vars]
ansible_user=global_user ; comment
timezone=UTC # comment

[web]
web1 ansible_host=192.168.1.11 http_port=8080
web2 ansible_host=192.168.1.12

[web:vars]
timezone=Europe/Stockholm
http_port=80

[db]
db1 ansible_host=192.168.1.21
db2 ansible_host=192.168.1.22 db_engine=postgres

[db:vars]
ansible_user=db_admin
backup_enabled=true

[app:children]
web
db

[app:vars]
timezone=Europe/Berlin
app_env=production

[test]
test1 ansible_host=10.0.0.11
test2 ansible_host=10.0.0.12 ansible_user=test_user

[test:vars]
app_env=staging
http_port=8081
`

	inv, err := inventory.ParseINI([]byte(src))
	require.NoError(t, err)

	tests := []struct {
		hostName string
		expected vars.Vars
	}{
		{
			hostName: "web1",
			expected: vars.Vars{
				"ansible_user": "global_user",      // all:vars
				"timezone":     "Europe/Stockholm", // web:vars > app:vars > all:vars
				"http_port":    "8080",             // override host
				"ansible_host": "192.168.1.11",     // host variable
				"app_env":      "production",       // app:vars
			},
		},
		{
			hostName: "web2",
			expected: vars.Vars{
				"ansible_user": "global_user",      // all:vars
				"timezone":     "Europe/Stockholm", // app:vars > all:vars
				"http_port":    "80",               // web:vars
				"ansible_host": "192.168.1.12",     // host variable
				"app_env":      "production",       // app:vars
			},
		},
		{
			hostName: "db1",
			expected: vars.Vars{
				"ansible_user":   "db_admin",      // db:vars > all:vars
				"timezone":       "Europe/Berlin", // app:vars > all:vars
				"backup_enabled": "true",          // db:vars
				"ansible_host":   "192.168.1.21",  // host variable
				"app_env":        "production",    // app:vars
			},
		},
		{
			hostName: "db2",
			expected: vars.Vars{
				"ansible_user":   "db_admin",      // db:vars > all:vars
				"timezone":       "Europe/Berlin", // app:vars > all:vars
				"backup_enabled": "true",          // db:vars
				"db_engine":      "postgres",      // host variable
				"ansible_host":   "192.168.1.22",  // host variable
				"app_env":        "production",    // app:vars
			},
		},
		{
			hostName: "test1",
			expected: vars.Vars{
				"ansible_user": "global_user", // all:vars
				"timezone":     "UTC",         // all:vars
				"http_port":    "8081",        // test:vars
				"app_env":      "staging",     // test:vars
				"ansible_host": "10.0.0.11",   // host variable
			},
		},
		{
			hostName: "test2",
			expected: vars.Vars{
				"ansible_user": "test_user", // host override
				"timezone":     "UTC",       // all:vars
				"http_port":    "8081",      // test:vars
				"app_env":      "staging",   // test:vars
				"ansible_host": "10.0.0.12", // host variable
			},
		},
		{
			hostName: "ungrouped1",
			expected: vars.Vars{
				"ansible_user": "global_user",         // all:vars
				"timezone":     "UTC",                 // all:vars
				"description":  "standalone;# \"host", // host variable
				"ansible_host": "10.0.0.99",           // host variable
				"http_port":    "8080",                // ungrouped:vars
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.hostName, func(t *testing.T) {
			got := inv.ResolveVars(tt.hostName, nil)
			assert.Equal(t, tt.expected, got)
		})
	}
}
