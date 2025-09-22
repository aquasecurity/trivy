package inventory_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/inventory"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/ansible/vars"
)

func groupVar(val any) vars.Variable {
	return vars.NewVariable(val, vars.InvFileGroupPriority)
}

func hostVar(val any) vars.Variable {
	return vars.NewVariable(val, vars.InvFileHostPriority)
}

func extAllGroupVar(val any) vars.Variable {
	return vars.NewVariable(val, vars.InvExtAllGroupPriority)
}

func extGroupVar(val any) vars.Variable {
	return vars.NewVariable(val, vars.InvExtGroupPriority)
}

func extHostVar(val any) vars.Variable {
	return vars.NewVariable(val, vars.InvExtHostPriority)
}

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
				"location":     groupVar("dc1"),
				"tag":          hostVar("leafs1"),
				"os":           groupVar("eos"),
				"role":         hostVar("custom-leaf"),
				"environment":  groupVar("dev"),
				"ansible_host": hostVar("192.0.2.100"),
			},
		},
		{
			hostName: "leaf02",
			expected: vars.Vars{
				"location":     groupVar("dc1"),
				"os":           groupVar("eos"),
				"role":         groupVar("leaf"),
				"environment":  groupVar("dev"),
				"ansible_host": hostVar("192.0.2.110"),
			},
		},
		{
			hostName: "spine01",
			expected: vars.Vars{
				"location":     groupVar("dc1"),
				"os":           groupVar("linux"),
				"role":         groupVar("spine"),
				"environment":  groupVar("dev"),
				"ansible_host": hostVar("192.0.2.120"),
			},
		},
		{
			hostName: "spine02",
			expected: vars.Vars{
				"location":     groupVar("dc1"),
				"os":           hostVar("nxos"),
				"role":         groupVar("spine"),
				"environment":  groupVar("dev"),
				"ansible_host": hostVar("192.0.2.130"),
			},
		},
		{
			hostName: "webserver01",
			expected: vars.Vars{
				"location":     groupVar("dc1"),
				"os":           groupVar("linux"),
				"role":         groupVar("web"),
				"ansible_host": hostVar("192.0.2.140"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.hostName, func(t *testing.T) {
			got := inv.ResolveVars(tt.hostName, make(inventory.LoadedVars))
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
timezone = Europe/Stockholm
http_port=80

[db]
db1 ansible_host=192.168.1.21
db2 ansible_host=192.168.1.22 db_engine=postgres

[db:vars]
ansible_user=  "db_admin"
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
				"ansible_user": groupVar("global_user"),
				"timezone":     groupVar("Europe/Stockholm"),
				"http_port":    hostVar("8080"),
				"ansible_host": hostVar("192.168.1.11"),
				"app_env":      groupVar("production"),
			},
		},
		{
			hostName: "web2",
			expected: vars.Vars{
				"ansible_user": groupVar("global_user"),
				"timezone":     groupVar("Europe/Stockholm"),
				"http_port":    groupVar("80"),
				"ansible_host": hostVar("192.168.1.12"),
				"app_env":      groupVar("production"),
			},
		},
		{
			hostName: "db1",
			expected: vars.Vars{
				"ansible_user":   groupVar("\"db_admin\""),
				"timezone":       groupVar("Europe/Berlin"),
				"backup_enabled": groupVar("true"),
				"ansible_host":   hostVar("192.168.1.21"),
				"app_env":        groupVar("production"),
			},
		},
		{
			hostName: "db2",
			expected: vars.Vars{
				"ansible_user":   groupVar("\"db_admin\""),
				"timezone":       groupVar("Europe/Berlin"),
				"backup_enabled": groupVar("true"),
				"db_engine":      hostVar("postgres"),
				"ansible_host":   hostVar("192.168.1.22"),
				"app_env":        groupVar("production"),
			},
		},
		{
			hostName: "test1",
			expected: vars.Vars{
				"ansible_user": groupVar("global_user"),
				"timezone":     groupVar("UTC"),
				"http_port":    groupVar("8081"),
				"app_env":      groupVar("staging"),
				"ansible_host": hostVar("10.0.0.11"),
			},
		},
		{
			hostName: "test2",
			expected: vars.Vars{
				"ansible_user": hostVar("test_user"),
				"timezone":     groupVar("UTC"),
				"http_port":    groupVar("8081"),
				"app_env":      groupVar("staging"),
				"ansible_host": hostVar("10.0.0.12"),
			},
		},
		{
			hostName: "ungrouped1",
			expected: vars.Vars{
				"ansible_user": groupVar("global_user"),
				"timezone":     groupVar("UTC"),
				"description":  hostVar("standalone;# \"host"),
				"ansible_host": hostVar("10.0.0.99"),
				"http_port":    groupVar("8080"),
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
