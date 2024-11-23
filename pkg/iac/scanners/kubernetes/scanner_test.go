package kubernetes_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/kubernetes"
)

func Test_ScanYAML(t *testing.T) {
	file := `
apiVersion: v1
kind: Pod
metadata: 
  name: hello-cpu-limit
spec: 
  containers: 
  - command: ["sh", "-c", "echo 'Hello' && sleep 1h"]
    image: busybox
    name: hello
`
	fsys := buildFS(map[string]string{
		"code/example.yaml": file,
		"checks/rule.rego": `# METADATA
# title: test check
# custom:
#   id: KSV011
#   avd_id: AVD-KSV-0011
#   severity: LOW
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV011

import data.lib.kubernetes

deny[res] {
	container := kubernetes.containers[_]
	res := result.new("fail", container)
}
`,
	})

	scanner := kubernetes.NewScanner(
		rego.WithPolicyFilesystem(fsys),
		rego.WithPolicyDirs("checks"),
		rego.WithEmbeddedLibraries(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fsys, "code")
	require.NoError(t, err)

	failed := results.GetFailed()
	require.Len(t, failed, 1)

	assert.Equal(t, "AVD-KSV-0011", failed[0].Rule().AVDID)
	assertLines(t, file, failed)
}

func Test_ScanJSON(t *testing.T) {

	file := `
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {
    "name": "hello-cpu-limit"
  },
  "spec": {
    "containers": [
      {
        "command": [
          "sh",
          "-c",
          "echo 'Hello' && sleep 1h"
        ],
        "image": "busybox",
        "name": "hello"
      }
    ]
  }
}
`

	fsys := buildFS(map[string]string{
		"code/example.json": file,
		"checks/rule.rego": `# METADATA
# title: test check
# custom:
#   id: KSV011
#   avd_id: AVD-KSV-0011
#   severity: LOW
#   input:
#     selector:
#     - type: kubernetes
package builtin.kubernetes.KSV011

import data.lib.kubernetes

deny[res] {
	container := kubernetes.containers[_]
	res := result.new("fail", container)
}
`,
	})

	scanner := kubernetes.NewScanner(
		rego.WithPolicyFilesystem(fsys),
		rego.WithPolicyDirs("checks"),
		rego.WithEmbeddedLibraries(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fsys, "code")
	require.NoError(t, err)

	require.Len(t, results.GetFailed(), 1)

	failed := results.GetFailed()
	require.Len(t, failed, 1)

	assert.Equal(t, "AVD-KSV-0011", failed[0].Rule().AVDID)
	assertLines(t, file, failed)
}

func Test_YamlWithSeparator(t *testing.T) {

	fsys := buildFS(map[string]string{
		"check.rego": `package defsec

deny[res] {
  input.kind == "Pod"
  res := result.new("fail", input)
}`,
		"k8s.yaml": `
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
`,
	})

	scanner := kubernetes.NewScanner(
		rego.WithPolicyFilesystem(fsys),
		rego.WithPolicyDirs("."),
		rego.WithEmbeddedLibraries(true),
	)
	results, err := scanner.ScanFS(context.TODO(), fsys, ".")
	require.NoError(t, err)

	assert.NotEmpty(t, results.GetFailed())
}

func Test_YamlMultiDocument(t *testing.T) {
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
	fsys := buildFS(map[string]string{
		"check.rego": `package defsec

deny[res] {
  input.kind == "Pod"
  res := result.new("fail", input)
}`,
		"k8s.yaml": file,
	})

	scanner := kubernetes.NewScanner(
		rego.WithPolicyFilesystem(fsys),
		rego.WithPolicyDirs("."),
		rego.WithEmbeddedLibraries(true),
	)

	results, err := scanner.ScanFS(context.TODO(), fsys, ".")
	require.NoError(t, err)

	assertLines(t, file, results)
}

func Test_CheckWithSubtype(t *testing.T) {
	fsys := buildFS(map[string]string{
		"checks/pod_policy.rego": `# METADATA
# title: test check
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: KSV001
#   avd_id: AVD-KSV-0001
#   severity: MEDIUM
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: Pod
package builtin.kubernetes.KSV001

import data.lib.kubernetes

deny[res] {
  res := result.new("fail", input)
}
`,
		"checks/namespace_policy.rego": `# METADATA
# title: test check 2
# scope: package
# schemas:
# - input: schema["kubernetes"]
# custom:
#   id: KSV002
#   avd_id: AVD-KSV-0002
#   severity: LOW
#   input:
#     selector:
#     - type: kubernetes
#       subtypes:
#         - kind: Namespace
package builtin.kubernetes.KSV002

deny[res] {
  res := result.new("fail", input)
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

	scanner := kubernetes.NewScanner(
		rego.WithEmbeddedLibraries(true),
		rego.WithPolicyDirs("checks"),
		rego.WithPolicyFilesystem(fsys),
	)
	results, err := scanner.ScanFS(context.TODO(), fsys, "test/KSV001")
	require.NoError(t, err)

	require.NoError(t, err)
	require.Len(t, results.GetFailed(), 1)

	failure := results.GetFailed()[0]

	assert.Equal(t, "AVD-KSV-0001", failure.Rule().AVDID)
}

func assertLines(t *testing.T, content string, results scan.Results) {
	lines := strings.Split(content, "\n")
	for _, res := range results {
		actualCode, err := res.GetCode()
		require.NoError(t, err)
		assert.NotEmpty(t, actualCode.Lines)
		for _, line := range actualCode.Lines {
			assert.Greater(t, len(lines), line.Number)
			assert.Equal(t, line.Content, lines[line.Number-1])
		}
	}
}

func buildFS(files map[string]string) fs.FS {
	return fstest.MapFS(lo.MapValues(files, func(val string, _ string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte(val)}
	}))
}
