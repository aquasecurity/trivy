package kubernetes

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_BasicScan(t *testing.T) {

	fs := testutil.CreateFS(t, map[string]string{
		"/code/example.yaml": `
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`,
		"/rules/lib.k8s.rego": `
 package lib.kubernetes

 default is_gatekeeper = false

 is_gatekeeper {
 	has_field(input, "review")
 	has_field(input.review, "object")
 }

 object = input {
 	not is_gatekeeper
 }

 object = input.review.object {
 	is_gatekeeper
 }

 format(msg) = gatekeeper_format {
 	is_gatekeeper
 	gatekeeper_format = {"msg": msg}
 }

 format(msg) = msg {
 	not is_gatekeeper
 }

 name = object.metadata.name

 default namespace = "default"

 namespace = object.metadata.namespace

 #annotations = object.metadata.annotations

 kind = object.kind

 is_pod {
 	kind = "Pod"
 }

 is_cronjob {
 	kind = "CronJob"
 }

 default is_controller = false

 is_controller {
 	kind = "Deployment"
 }

 is_controller {
 	kind = "StatefulSet"
 }

 is_controller {
 	kind = "DaemonSet"
 }

 is_controller {
 	kind = "ReplicaSet"
 }

 is_controller {
 	kind = "ReplicationController"
 }

 is_controller {
 	kind = "Job"
 }

 split_image(image) = [image, "latest"] {
 	not contains(image, ":")
 }

 split_image(image) = [image_name, tag] {
 	[image_name, tag] = split(image, ":")
 }

 pod_containers(pod) = all_containers {
 	keys = {"containers", "initContainers"}
 	all_containers = [c | keys[k]; c = pod.spec[k][_]]
 }

 containers[container] {
 	pods[pod]
 	all_containers = pod_containers(pod)
 	container = all_containers[_]
 }

 containers[container] {
 	all_containers = pod_containers(object)
 	container = all_containers[_]
 }

 pods[pod] {
 	is_pod
 	pod = object
 }

 pods[pod] {
 	is_controller
 	pod = object.spec.template
 }

 pods[pod] {
 	is_cronjob
 	pod = object.spec.jobTemplate.spec.template
 }

 volumes[volume] {
 	pods[pod]
 	volume = pod.spec.volumes[_]
 }

 dropped_capability(container, cap) {
 	container.securityContext.capabilities.drop[_] == cap
 }

 added_capability(container, cap) {
 	container.securityContext.capabilities.add[_] == cap
 }

 has_field(obj, field) {
 	obj[field]
 }

 no_read_only_filesystem(c) {
 	not has_field(c, "securityContext")
 }

 no_read_only_filesystem(c) {
 	has_field(c, "securityContext")
 	not has_field(c.securityContext, "readOnlyRootFilesystem")
 }

 privilege_escalation_allowed(c) {
 	not has_field(c, "securityContext")
 }

 privilege_escalation_allowed(c) {
 	has_field(c, "securityContext")
 	has_field(c.securityContext, "allowPrivilegeEscalation")
 }

 annotations[annotation] {
 	pods[pod]
 	annotation = pod.metadata.annotations
 }

 host_ipcs[host_ipc] {
 	pods[pod]
 	host_ipc = pod.spec.hostIPC
 }

 host_networks[host_network] {
 	pods[pod]
 	host_network = pod.spec.hostNetwork
 }

 host_pids[host_pid] {
 	pods[pod]
 	host_pid = pod.spec.hostPID
 }

 host_aliases[host_alias] {
 	pods[pod]
 	host_alias = pod.spec
 }
 `,
		"/rules/lib.util.rego": `
 package lib.utils

 has_key(x, k) {
 	_ = x[k]
 }`,
		"/rules/rule.rego": `
package builtin.kubernetes.KSV011

import data.lib.kubernetes
import data.lib.utils

default failLimitsCPU = false

__rego_metadata__ := {
	"id": "KSV011",
	"avd_id": "AVD-KSV-0011",
	"title": "CPU not limited",
	"short_code": "limit-cpu",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Enforcing CPU limits prevents DoS via resource exhaustion.",
	"recommended_actions": "Set a limit value under 'containers[].resources.limits.cpu'.",
	"url": "https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getLimitsCPUContainers returns all containers which have set resources.limits.cpu
getLimitsCPUContainers[container] {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.resources.limits, "cpu")
	container := allContainers.name
}

# getNoLimitsCPUContainers returns all containers which have not set
# resources.limits.cpu
getNoLimitsCPUContainers[container] {
	container := kubernetes.containers[_].name
	not getLimitsCPUContainers[container]
}

# failLimitsCPU is true if containers[].resources.limits.cpu is not set
# for ANY container
failLimitsCPU {
	count(getNoLimitsCPUContainers) > 0
}

deny[res] {
	failLimitsCPU

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'resources.limits.cpu'", [getNoLimitsCPUContainers[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
        "startline": 6,
        "endline": 10,
	}
}
`,
	})

	scanner := NewScanner(options.ScannerWithPolicyDirs("rules"))

	results, err := scanner.ScanFS(context.TODO(), fs, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	assert.Equal(t, scan.Rule{
		AVDID:          "AVD-KSV-0011",
		Aliases:        []string{"KSV011"},
		ShortCode:      "limit-cpu",
		Summary:        "CPU not limited",
		Explanation:    "Enforcing CPU limits prevents DoS via resource exhaustion.",
		Impact:         "",
		Resolution:     "Set a limit value under 'containers[].resources.limits.cpu'.",
		Provider:       "kubernetes",
		Service:        "general",
		Links:          []string{"https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits"},
		Severity:       "LOW",
		Terraform:      &scan.EngineMetadata{},
		CloudFormation: &scan.EngineMetadata{},
		CustomChecks:   scan.CustomChecks{Terraform: (*scan.TerraformCustomCheck)(nil)},
		RegoPackage:    "data.builtin.kubernetes.KSV011",
		Frameworks:     map[framework.Framework][]string{},
	}, results.GetFailed()[0].Rule())

	failure := results.GetFailed()[0]
	actualCode, err := failure.GetCode()
	require.NoError(t, err)
	for i := range actualCode.Lines {
		actualCode.Lines[i].Highlighted = ""
	}
	assert.Equal(t, []scan.Line{
		{
			Number:     6,
			Content:    "spec: ",
			IsCause:    true,
			FirstCause: true,
			Annotation: "",
		},
		{
			Number:     7,
			Content:    "  containers: ",
			IsCause:    true,
			Annotation: "",
		},
		{
			Number:     8,
			Content:    "  - command: [\"sh\", \"-c\", \"echo 'Hello' && sleep 1h\"]",
			IsCause:    true,
			Annotation: "",
		},
		{
			Number:     9,
			Content:    "    image: busybox",
			IsCause:    true,
			Annotation: "",
		},
		{
			Number:     10,
			Content:    "    name: hello",
			IsCause:    true,
			LastCause:  true,
			Annotation: "",
		},
	}, actualCode.Lines)
}

func Test_FileScan(t *testing.T) {

	results, err := NewScanner(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true), options.ScannerWithEmbeddedLibraries(true)).ScanReader(context.TODO(), "k8s.yaml", strings.NewReader(`
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`))
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)
}

func Test_FileScan_WithSeparator(t *testing.T) {

	results, err := NewScanner(options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true)).ScanReader(context.TODO(), "k8s.yaml", strings.NewReader(`
---
---
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`))
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)
}

func Test_FileScan_MultiManifests(t *testing.T) {
	file := `
---
apiVersion: v1
kind: Pod
metadata: 
  name: hello1-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello1' && sleep 1h"]
    image: busybox
    name: hello1
---
apiVersion: v1
kind: Pod
metadata: 
  name: hello2-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello2' && sleep 1h"]
    image: busybox
    name: hello2
`

	results, err := NewScanner(
		options.ScannerWithEmbeddedPolicies(true),
		options.ScannerWithEmbeddedLibraries(true),
		options.ScannerWithEmbeddedLibraries(true)).ScanReader(context.TODO(), "k8s.yaml", strings.NewReader(file))
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 1)
	fileLines := strings.Split(file, "\n")
	for _, failure := range results.GetFailed() {
		actualCode, err := failure.GetCode()
		require.NoError(t, err)
		assert.Greater(t, len(actualCode.Lines), 0)
		for _, line := range actualCode.Lines {
			assert.Greater(t, len(fileLines), line.Number)
			assert.Equal(t, line.Content, fileLines[line.Number-1])
		}
	}
}

func Test_FileScanWithPolicyReader(t *testing.T) {

	results, err := NewScanner(options.ScannerWithPolicyReader(strings.NewReader(`package defsec

deny[msg] {
  msg = "fail"
}
`))).ScanReader(context.TODO(), "k8s.yaml", strings.NewReader(`
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`))
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
}

func Test_FileScanJSON(t *testing.T) {

	results, err := NewScanner(options.ScannerWithPolicyReader(strings.NewReader(`package defsec

deny[msg] {
  input.kind == "Pod"
  msg = "fail"
}
`))).ScanReader(context.TODO(), "k8s.json", strings.NewReader(`
{
  "kind": "Pod",
  "apiVersion": "v1",
  "metadata": {
    "name": "mongo",
    "labels": {
      "name": "mongo",
      "role": "mongo"
    }
  },
  "spec": {
    "volumes": [
      {
        "name": "mongo-disk",
        "gcePersistentDisk": {
          "pdName": "mongo-disk",
          "fsType": "ext4"
        }
      }
    ],
    "containers": [
      {
        "name": "mongo",
        "image": "mongo:latest",
        "ports": [
          {
            "name": "mongo",
            "containerPort": 27017
          }
        ],
        "volumeMounts": [
          {
            "name": "mongo-disk",
            "mountPath": "/data/db"
          }
        ]
      }
    ]
  }
}
`))
	require.NoError(t, err)

	assert.Equal(t, 1, len(results.GetFailed()))
}

func Test_FileScanWithMetadata(t *testing.T) {

	results, err := NewScanner(
		options.ScannerWithDebug(os.Stdout),
		options.ScannerWithTrace(os.Stdout),
		options.ScannerWithPolicyReader(strings.NewReader(`package defsec

deny[msg] {
  input.kind == "Pod"
  msg := {
          "msg": "fail",
          "startline": 2,
		  "endline": 2,
          "filepath": "chartname/template/serviceAccount.yaml"
        }
}
`))).ScanReader(
		context.TODO(),
		"k8s.yaml",
		strings.NewReader(`
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`))
	require.NoError(t, err)

	assert.Greater(t, len(results.GetFailed()), 0)

	firstResult := results.GetFailed()[0]
	assert.Equal(t, 2, firstResult.Metadata().Range().GetStartLine())
	assert.Equal(t, 2, firstResult.Metadata().Range().GetEndLine())
	assert.Equal(t, "chartname/template/serviceAccount.yaml", firstResult.Metadata().Range().GetFilename())
}

func Test_FileScanExampleWithResultFunction(t *testing.T) {

	results, err := NewScanner(
		options.ScannerWithDebug(os.Stdout),
		options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true),
		options.ScannerWithPolicyReader(strings.NewReader(`package defsec

import data.lib.kubernetes

default checkCapsDropAll = false

__rego_metadata__ := {
"id": "KSV003",
"avd_id": "AVD-KSV-0003",
"title": "Default capabilities not dropped",
"short_code": "drop-default-capabilities",
"version": "v1.0.0",
"severity": "LOW",
"type": "Kubernetes Security Check",
"description": "The container should drop all default capabilities and add only those that are needed for its execution.",
"recommended_actions": "Add 'ALL' to containers[].securityContext.capabilities.drop.",
"url": "https://kubesec.io/basics/containers-securitycontext-capabilities-drop-index-all/",
}

__rego_input__ := {
"combine": false,
"selector": [{"type": "kubernetes"}],
}

# Get all containers which include 'ALL' in security.capabilities.drop
getCapsDropAllContainers[container] {
allContainers := kubernetes.containers[_]
lower(allContainers.securityContext.capabilities.drop[_]) == "all"
container := allContainers.name
}

# Get all containers which don't include 'ALL' in security.capabilities.drop
getCapsNoDropAllContainers[container] {
container := kubernetes.containers[_]
not getCapsDropAllContainers[container.name]
}

deny[res] {
output := getCapsNoDropAllContainers[_]

msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should add 'ALL' to 'securityContext.capabilities.drop'", [output.name, kubernetes.kind, kubernetes.name]))

res := result.new(msg, output)
}

`))).ScanReader(
		context.TODO(),
		"k8s.yaml",
		strings.NewReader(`
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
    securityContext:
      capabilities:
        drop:
        - nothing
`))
	require.NoError(t, err)

	require.Greater(t, len(results.GetFailed()), 0)

	firstResult := results.GetFailed()[0]
	assert.Equal(t, 8, firstResult.Metadata().Range().GetStartLine())
	assert.Equal(t, 14, firstResult.Metadata().Range().GetEndLine())
	assert.Equal(t, "k8s.yaml", firstResult.Metadata().Range().GetFilename())
}

func Test_checkPolicyIsApplicable(t *testing.T) {
	srcFS := testutil.CreateFS(t, map[string]string{
		"policies/pod_policy.rego": `# METADATA
# title: "Process can elevate its own privileges"
# description: "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node."
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
# custom:
#   id: KSV001
#   avd_id: AVD-KSV-0999
#   severity: MEDIUM
#   short_code: no-self-privesc
#   recommended_action: "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: Pod
package builtin.kubernetes.KSV999

import data.lib.kubernetes
import data.lib.utils

default checkAllowPrivilegeEscalation = false

# getNoPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to false.
getNoPrivilegeEscalationContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.allowPrivilegeEscalation == false
	container := allContainers.name
}

# getPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to true or not set.
getPrivilegeEscalationContainers[container] {
	containerName := kubernetes.containers[_].name
	not getNoPrivilegeEscalationContainers[containerName]
	container := kubernetes.containers[_]
}

deny[res] {
	output := getPrivilegeEscalationContainers[_]
	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set 'securityContext.allowPrivilegeEscalation' to false", [output.name, kubernetes.kind, kubernetes.name]))
	res := result.new(msg, output)
}

`,
		"policies/namespace_policy.rego": `# METADATA
# title: "The default namespace should not be used"
# description: "ensure that default namespace should not be used"
# scope: package
# schemas:
# - input: schema["kubernetes"]
# related_resources:
# - https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
# custom:
#   id: KSV110
#   avd_id: AVD-KSV-0888
#   severity: LOW
#   short_code: default-namespace-should-not-be-used
#   recommended_action: "Ensure that namespaces are created to allow for appropriate segregation of Kubernetes resources and that all new resources are created in a specific namespace."
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: Namespace
package builtin.kubernetes.KSV888

import data.lib.kubernetes

default defaultNamespaceInUse = false

defaultNamespaceInUse {
	kubernetes.namespace == "default"
}

deny[res] {
	defaultNamespaceInUse
	msg := sprintf("%s '%s' should not be set with 'default' namespace", [kubernetes.kind, kubernetes.name])
	res := result.new(msg, input.metadata.namespace)
}

`,
		"test/KSV001/pod.yaml": `apiVersion: v1
kind: Pod
metadata:
  name: hello-cpu-limit
spec:
  containers:
    - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
      image: busybox
      name: hello
      securityContext:
        capabilities:
          drop:
            - all
`,
	})

	scanner := NewScanner(
		// options.ScannerWithEmbeddedPolicies(true), options.ScannerWithEmbeddedLibraries(true),
		options.ScannerWithEmbeddedLibraries(true),
		options.ScannerWithPolicyDirs("policies/"),
		options.ScannerWithPolicyFilesystem(srcFS),
	)
	results, err := scanner.ScanFS(context.TODO(), srcFS, "test/KSV001")
	require.NoError(t, err)

	require.NoError(t, err)
	require.Len(t, results.GetFailed(), 1)

	failure := results.GetFailed()[0].Rule()
	assert.Equal(t, "Process can elevate its own privileges", failure.Summary)
}
