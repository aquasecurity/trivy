package flag

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
)

var (
	ClusterContextFlag = Flag[string]{
		Name:       "context",
		ConfigName: "kubernetes.context",
		Usage:      "specify a context to scan",
		Aliases: []Alias{
			{Name: "ctx"},
		},
	}
	K8sNamespaceFlag = Flag[string]{
		Name:       "namespace",
		ConfigName: "kubernetes.namespace",
		Shorthand:  "n",
		Usage:      "specify a namespace to scan",
	}
	KubeConfigFlag = Flag[string]{
		Name:       "kubeconfig",
		ConfigName: "kubernetes.kubeconfig",
		Usage:      "specify the kubeconfig file path to use",
	}
	ComponentsFlag = Flag[[]string]{
		Name:       "components",
		ConfigName: "kubernetes.components",
		Default: []string{
			"workload",
			"infra",
		},
		Values: []string{
			"workload",
			"infra",
		},
		Usage: "specify which components to scan",
	}
	K8sVersionFlag = Flag[string]{
		Name:       "k8s-version",
		ConfigName: "kubernetes.k8s.version",
		Usage:      "specify k8s version to validate outdated api by it (example: 1.21.0)",
	}
	TolerationsFlag = Flag[[]string]{
		Name:       "tolerations",
		ConfigName: "kubernetes.tolerations",
		Usage:      "specify node-collector job tolerations (example: key1=value1:NoExecute,key2=value2:NoSchedule)",
	}
	AllNamespaces = Flag[bool]{
		Name:       "all-namespaces",
		ConfigName: "kubernetes.all.namespaces",
		Shorthand:  "A",
		Usage:      "fetch resources from all cluster namespaces",
	}
	NodeCollectorNamespace = Flag[string]{
		Name:       "node-collector-namespace",
		ConfigName: "node.collector.namespace",
		Default:    "trivy-temp",
		Usage:      "specify the namespace in which the node-collector job should be deployed",
	}
	ExcludeOwned = Flag[bool]{
		Name:       "exclude-owned",
		ConfigName: "kubernetes.exclude.owned",
		Usage:      "exclude resources that have an owner reference",
	}
	ExcludeNodes = Flag[[]string]{
		Name:       "exclude-nodes",
		ConfigName: "kubernetes.exclude.nodes",
		Usage:      "indicate the node labels that the node-collector job should exclude from scanning (example: kubernetes.io/arch:arm64,team:dev)",
	}
	NodeCollectorImageRef = Flag[string]{
		Name:       "node-collector-imageref",
		ConfigName: "kubernetes.node.collector.imageref",
		Default:    "ghcr.io/aquasecurity/node-collector:0.0.9",
		Usage:      "indicate the image reference for the node-collector scan job",
	}
	QPS = Flag[float64]{
		Name:       "qps",
		ConfigName: "kubernetes.qps",
		Default:    5.0,
		Usage:      "specify the maximum QPS to the master from this client",
	}
	Burst = Flag[int]{
		Name:       "burst",
		ConfigName: "kubernetes.burst",
		Default:    10,
		Usage:      "specify the maximum burst for throttle",
	}
)

type K8sFlagGroup struct {
	ClusterContext         *Flag[string]
	Namespace              *Flag[string]
	KubeConfig             *Flag[string]
	Components             *Flag[[]string]
	K8sVersion             *Flag[string]
	Tolerations            *Flag[[]string]
	NodeCollectorImageRef  *Flag[string]
	AllNamespaces          *Flag[bool]
	NodeCollectorNamespace *Flag[string]
	ExcludeOwned           *Flag[bool]
	ExcludeNodes           *Flag[[]string]
	QPS                    *Flag[float64]
	Burst                  *Flag[int]
}

type K8sOptions struct {
	ClusterContext         string
	Namespace              string
	KubeConfig             string
	Components             []string
	K8sVersion             string
	Tolerations            []corev1.Toleration
	NodeCollectorImageRef  string
	AllNamespaces          bool
	NodeCollectorNamespace string
	ExcludeOwned           bool
	ExcludeNodes           map[string]string
	QPS                    float32
	Burst                  int
}

func NewK8sFlagGroup() *K8sFlagGroup {
	return &K8sFlagGroup{
		ClusterContext:         ClusterContextFlag.Clone(),
		Namespace:              K8sNamespaceFlag.Clone(),
		KubeConfig:             KubeConfigFlag.Clone(),
		Components:             ComponentsFlag.Clone(),
		K8sVersion:             K8sVersionFlag.Clone(),
		Tolerations:            TolerationsFlag.Clone(),
		AllNamespaces:          AllNamespaces.Clone(),
		NodeCollectorNamespace: NodeCollectorNamespace.Clone(),
		ExcludeOwned:           ExcludeOwned.Clone(),
		ExcludeNodes:           ExcludeNodes.Clone(),
		NodeCollectorImageRef:  NodeCollectorImageRef.Clone(),
		QPS:                    QPS.Clone(),
		Burst:                  Burst.Clone(),
	}
}

func (f *K8sFlagGroup) Name() string {
	return "Kubernetes"
}

func (f *K8sFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.ClusterContext,
		f.Namespace,
		f.KubeConfig,
		f.Components,
		f.K8sVersion,
		f.Tolerations,
		f.AllNamespaces,
		f.NodeCollectorNamespace,
		f.ExcludeOwned,
		f.ExcludeNodes,
		f.NodeCollectorImageRef,
		f.QPS,
		f.Burst,
	}
}

func (f *K8sFlagGroup) ToOptions() (K8sOptions, error) {
	if err := parseFlags(f); err != nil {
		return K8sOptions{}, err
	}

	tolerations, err := optionToTolerations(f.Tolerations.Value())
	if err != nil {
		return K8sOptions{}, err
	}

	exludeNodeLabels := make(map[string]string)
	exludeNodes := f.ExcludeNodes.Value()
	for _, exludeNodeValue := range exludeNodes {
		excludeNodeParts := strings.Split(exludeNodeValue, ":")
		if len(excludeNodeParts) != 2 {
			return K8sOptions{}, fmt.Errorf("exclude node %s must be a key:value", exludeNodeValue)
		}
		exludeNodeLabels[excludeNodeParts[0]] = excludeNodeParts[1]
	}

	return K8sOptions{
		ClusterContext:         f.ClusterContext.Value(),
		Namespace:              f.Namespace.Value(),
		KubeConfig:             f.KubeConfig.Value(),
		Components:             f.Components.Value(),
		K8sVersion:             f.K8sVersion.Value(),
		Tolerations:            tolerations,
		AllNamespaces:          f.AllNamespaces.Value(),
		NodeCollectorNamespace: f.NodeCollectorNamespace.Value(),
		ExcludeOwned:           f.ExcludeOwned.Value(),
		ExcludeNodes:           exludeNodeLabels,
		NodeCollectorImageRef:  f.NodeCollectorImageRef.Value(),
		QPS:                    float32(f.QPS.Value()),
		Burst:                  f.Burst.Value(),
	}, nil
}

func optionToTolerations(tolerationsOptions []string) ([]corev1.Toleration, error) {
	var tolerations []corev1.Toleration
	for _, toleration := range tolerationsOptions {
		tolerationParts := strings.Split(toleration, ":")
		if len(tolerationParts) < 2 {
			return []corev1.Toleration{}, fmt.Errorf("toleration must include key and effect")
		}
		if corev1.TaintEffect(tolerationParts[1]) != corev1.TaintEffectNoSchedule &&
			corev1.TaintEffect(tolerationParts[1]) != corev1.TaintEffectPreferNoSchedule &&
			corev1.TaintEffect(tolerationParts[1]) != corev1.TaintEffectNoExecute {
			return []corev1.Toleration{}, fmt.Errorf("toleration effect must be a valid value")
		}
		keyValue := strings.Split(tolerationParts[0], "=")
		operator := corev1.TolerationOpEqual
		if keyValue[1] == "" {
			operator = corev1.TolerationOpExists
		}
		toleration := corev1.Toleration{
			Key:      keyValue[0],
			Value:    keyValue[1],
			Operator: operator,
			Effect:   corev1.TaintEffect(tolerationParts[1]),
		}
		var tolerationSec int
		var err error
		if len(tolerationParts) == 3 {
			tolerationSec, err = strconv.Atoi(tolerationParts[2])
			if err != nil {
				return nil, fmt.Errorf("TolerationSeconds must must be a number")
			}
			toleration.TolerationSeconds = lo.ToPtr(int64(tolerationSec))
		}
		tolerations = append(tolerations, toleration)
	}
	return tolerations, nil
}
