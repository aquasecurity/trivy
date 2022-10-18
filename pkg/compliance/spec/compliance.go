package spec

import (
	"github.com/mitchellh/mapstructure"
)

const NsaSpec = `
---
spec:
  id: "0001"
  title: nsa
  description: National Security Agency - Kubernetes Hardening Guidance
  relatedResources : 
    - https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/nsa-cisa-release-kubernetes-hardening-guidance/
  version: "1.0"
  controls:
    - name: Non-root containers
      description: 'Check that container is not running as root'
      id: '1.0'
      checks:
        - id: AVD-KSV-0012
      severity: 'MEDIUM'
    - name: Immutable container file systems
      description: 'Check that container root file system is immutable'
      id: '1.1'
      checks:
        - id: AVD-KSV-0014
      severity: 'LOW'
    - name: Preventing privileged containers
      description: 'Controls whether Pods can run privileged containers'
      id: '1.2'
      checks:
        - id: AVD-KSV-0017
      severity: 'HIGH'
    - name: Share containers process namespaces
      description: 'Controls whether containers can share process namespaces'
      id: '1.3'
      checks:
        - id: AVD-KSV-0008
      severity: 'HIGH'
    - name: Share host process namespaces
      description: 'Controls whether share host process namespaces'
      id: '1.4'
      checks:
        - id: AVD-KSV-0009
      severity: 'HIGH'
    - name: Use the host network
      description: 'Controls whether containers can use the host network'
      id: '1.5'
      checks:
        - id: AVD-KSV-0010
      severity: 'HIGH'
    - name:  Run with root privileges or with root group membership
      description: 'Controls whether container applications can run with root privileges or with root group membership'
      id: '1.6'
      checks:
        - id: AVD-KSV-0029
      severity: 'LOW'
    - name: Restricts escalation to root privileges
      description: 'Control check restrictions escalation to root privileges'
      id: '1.7'
      checks:
        - id: AVD-KSV-0001
      severity: 'MEDIUM'
    - name: Sets the SELinux context of the container
      description: 'Control checks if pod sets the SELinux context of the container'
      id: '1.8'
      checks:
        - id: AVD-KSV-0002
      severity: 'MEDIUM'
    - name: Restrict a container's access to resources with AppArmor
      description: 'Control checks the restriction of containers access to resources with AppArmor'
      id: '1.9'
      checks:
        - id: AVD-KSV-0030
      severity: 'MEDIUM'
    - name: Sets the seccomp profile used to sandbox containers.
      description: 'Control checks the sets the seccomp profile used to sandbox containers'
      id: '1.10'
      checks:
        - id: AVD-KSV-0030
      severity: 'LOW'
    - name: Protecting Pod service account tokens
      description: 'Control check whether disable secret token been mount ,automountServiceAccountToken: false'
      id: '1.11'
      checks:
        - id: AVD-KSV-0036
      severity: 'MEDIUM'
    - name: Namespace kube-system should not be used by users
      description: 'Control check whether Namespace kube-system is not be used by users'
      id: '1.12'
      defaultStatus: 'FAIL'
      checks:
        - id: AVD-KSV-0037
      severity: 'MEDIUM'
    - name: Pod and/or namespace Selectors usage
      description: 'Control check validate the pod and/or namespace Selectors usage'
      id: '2.0'
      defaultStatus: 'FAIL'
      checks:
        - id: AVD-KSV-0038
      severity: 'MEDIUM'
    - name: Use CNI plugin that supports NetworkPolicy API
      description: 'Control check whether check cni plugin installed'
      id: '3.0'
      checks:
        - id: CVE-5.3.1
      severity: 'CRITICAL'
    - name: Use ResourceQuota policies to limit resources
      description: 'Control check the use of ResourceQuota policy to limit aggregate resource usage within namespace'
      id: '4.0'
      defaultStatus: 'FAIL'
      checks:
        - id: AVD-KSV-0040
      severity: 'MEDIUM'
    - name: Use LimitRange policies to limit resources
      description: 'Control check the use of LimitRange policy limit resource usage for namespaces or nodes'
      id: '4.1'
      defaultStatus: 'FAIL'
      checks:
        - id: AVD-KSV-0039
      severity: 'MEDIUM'
    - name: Control plan disable insecure port
      description: 'Control check whether control plan disable insecure port'
      id: '5.0'
      checks:
        - id: CVE-1.2.19
      severity: 'CRITICAL'
    - name: Encrypt etcd communication
      description: 'Control check whether etcd communication is encrypted'
      id: '5.1'
      checks:
        - id: CVE-2.1
      severity: 'CRITICAL'
    - name: Ensure kube config file permission
      description: 'Control check whether kube config file permissions'
      id: '6.0'
      checks:
        - id: CVE-4.1.3
        - id: CVE-4.1.4
      severity: 'CRITICAL'
    - name: Check that encryption resource has been set
      description: 'Control checks whether encryption resource has been set'
      id: '6.1'
      checks:
        - id: CVE-1.2.31
        - id: CVE-1.2.32
      severity: 'CRITICAL'
    - name: Check encryption provider
      description: 'Control checks whether encryption provider has been set'
      id: '6.2'
      checks:
        - id: CVE-1.2.3
      severity: 'CRITICAL'
    - name: Make sure anonymous-auth is unset
      description: 'Control checks whether anonymous-auth is unset'
      id: '7.0'
      checks:
        - id: CVE-1.2.1
      severity: 'CRITICAL'
    - name: Make sure -authorization-mode=RBAC
      description: 'Control check whether RBAC permission is in use'
      id: '7.1'
      checks:
        - id: CVE-1.2.7
        - id: CVE-1.2.8
      severity: 'CRITICAL'
    - name: Audit policy is configure
      description: 'Control check whether audit policy is configure'
      id: '8.0'
      checks:
        - id: CVE-3.2.1
      severity: 'HIGH'
    - name: Audit log path is configure
      description: 'Control check whether audit log path is configure'
      id: '8.1'
      checks:
        - id: CVE-1.2.22
      severity: 'MEDIUM'
    - name: Audit log aging
      description: 'Control check whether audit log aging is configure'
      id: '8.2'
      checks:
        - id: CVE-1.2.23
      severity: 'MEDIUM'
`

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"

	SeverityNone    Severity = "NONE"
	SeverityUnknown Severity = "UNKNOWN"
)

// ComplianceSpec represent the compliance specification
type ComplianceSpec struct {
	Spec Spec `yaml:"spec"`
}

type Spec struct {
	ID               string    `yaml:"id"`
	Title            string    `yaml:"title"`
	Description      string    `yaml:"description"`
	Version          string    `yaml:"version"`
	RelatedResources []string  `yaml:"relatedResources"`
	Controls         []Control `yaml:"controls"`
}

// Control represent the cps controls data and mapping checks
type Control struct {
	ID            string        `yaml:"id"`
	Name          string        `yaml:"name"`
	Description   string        `yaml:"description,omitempty"`
	Checks        []SpecCheck   `yaml:"checks"`
	Severity      Severity      `yaml:"severity"`
	DefaultStatus ControlStatus `yaml:"defaultStatus,omitempty"`
}

// SpecCheck represent the scanner who perform the control check
type SpecCheck struct {
	ID string `yaml:"id"`
}

// ControlCheck provides the result of conducting a single audit step.
type ControlCheck struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	PassTotal   int      `yaml:"passTotal"`
	FailTotal   int      `yaml:"failTotal"`
	Severity    Severity `yaml:"severity"`
}

type ControlStatus string

const (
	FailStatus ControlStatus = "FAIL"
	PassStatus ControlStatus = "PASS"
	WarnStatus ControlStatus = "WARN"
)

// UnmarshalYAML over unmarshall to add logic
func (r *ComplianceSpec) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var res map[string]interface{}
	if err := unmarshal(&res); err != nil {
		return err
	}
	err := mapstructure.Decode(res, &r)
	if err != nil {
		return err
	}
	return ValidateScanners(r.Spec.Controls)
}
