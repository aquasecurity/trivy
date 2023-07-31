package flag

import (
	"strconv"

	"fmt"
	"strings"

	"golang.org/x/xerrors"

	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
)

var (
	ClusterContextFlag = Flag{
		Name:       "context",
		ConfigName: "kubernetes.context",
		Default:    "",
		Usage:      "specify a context to scan",
		Aliases: []Alias{
			{Name: "ctx"},
		},
	}
	K8sNamespaceFlag = Flag{
		Name:       "namespace",
		ConfigName: "kubernetes.namespace",
		Shorthand:  "n",
		Default:    "",
		Usage:      "specify a namespace to scan",
	}
	KubeConfigFlag = Flag{
		Name:       "kubeconfig",
		ConfigName: "kubernetes.kubeconfig",
		Default:    "",
		Usage:      "specify the kubeconfig file path to use",
	}
	ComponentsFlag = Flag{
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
	K8sVersionFlag = Flag{
		Name:       "k8s-version",
		ConfigName: "kubernetes.k8s.version",
		Default:    "",
		Usage:      "specify k8s version to validate outdated api by it (example: 1.21.0)",
	}
	ParallelFlag = Flag{
		Name:       "parallel",
		ConfigName: "kubernetes.parallel",
		Default:    5,
		Usage:      "number (between 1-20) of goroutines enabled for parallel scanning",
	}
	TolerationsFlag = Flag{
		Name:       "tolerations",
		ConfigName: "kubernetes.tolerations",
		Default:    []string{},
		Usage:      "specify node-collector job tolerations (example: key1=value1:NoExecute,key2=value2:NoSchedule)",
	}
	AllNamespaces = Flag{
		Name:       "all-namespaces",
		ConfigName: "kubernetes.all.namespaces",
		Shorthand:  "A",
		Default:    false,
		Usage:      "fetch resources from all cluster namespaces",
	}
	NodeCollectorNamespace = Flag{
		Name:       "node-collector-namespace",
		ConfigName: "node.collector.namespace",
		Default:    "trivy-temp",
		Usage:      "specify the namespace in which the node-collector job should be deployed",
	}
	ExcludeNodes = Flag{
		Name:       "exclude-nodes",
		ConfigName: "exclude.nodes",
		Default:    []string{},
		Usage:      "indicate the node labels that the node-collector job should exclude from scanning (example: kubernetes.io/arch:arm64,team:dev)",
	}
)

type K8sFlagGroup struct {
	ClusterContext         *Flag
	Namespace              *Flag
	KubeConfig             *Flag
	Components             *Flag
	K8sVersion             *Flag
	Parallel               *Flag
	Tolerations            *Flag
	AllNamespaces          *Flag
	NodeCollectorNamespace *Flag
	ExcludeNodes           *Flag
}

type K8sOptions struct {
	ClusterContext         string
	Namespace              string
	KubeConfig             string
	Components             []string
	K8sVersion             string
	Parallel               int
	Tolerations            []corev1.Toleration
	AllNamespaces          bool
	NodeCollectorNamespace string
	ExcludeNodes           map[string]string
}

func NewK8sFlagGroup() *K8sFlagGroup {
	return &K8sFlagGroup{
		ClusterContext:         &ClusterContextFlag,
		Namespace:              &K8sNamespaceFlag,
		KubeConfig:             &KubeConfigFlag,
		Components:             &ComponentsFlag,
		K8sVersion:             &K8sVersionFlag,
		Parallel:               &ParallelFlag,
		Tolerations:            &TolerationsFlag,
		AllNamespaces:          &AllNamespaces,
		NodeCollectorNamespace: &NodeCollectorNamespace,
		ExcludeNodes:           &ExcludeNodes,
	}
}

func (f *K8sFlagGroup) Name() string {
	return "Kubernetes"
}

func (f *K8sFlagGroup) Flags() []*Flag {
	return []*Flag{
		f.ClusterContext,
		f.Namespace,
		f.KubeConfig,
		f.Components,
		f.K8sVersion,
		f.Parallel,
		f.Tolerations,
		f.AllNamespaces,
		f.NodeCollectorNamespace,
		f.ExcludeNodes,
	}
}

func (f *K8sFlagGroup) ToOptions() (K8sOptions, error) {
	tolerations, err := optionToTolerations(getStringSlice(f.Tolerations))
	if err != nil {
		return K8sOptions{}, err
	}
	var parallel int
	if f.Parallel != nil {
		parallel = getInt(f.Parallel)
		// check parallel flag is a valid number between 1-20
		if parallel < 1 || parallel > 20 {
			return K8sOptions{}, xerrors.Errorf("unable to parse parallel value, please ensure that the value entered is a valid number between 1-20.")
		}
	}
	exludeNodeLabels := make(map[string]string)
	exludeNodes := getStringSlice(f.ExcludeNodes)
	for _, exludeNodeValue := range exludeNodes {
		excludeNodeParts := strings.Split(exludeNodeValue, ":")
		if len(excludeNodeParts) != 2 {
			return K8sOptions{}, fmt.Errorf("exclude node %s must be a key:value", exludeNodeValue)
		}
		exludeNodeLabels[excludeNodeParts[0]] = excludeNodeParts[1]
	}

	return K8sOptions{
		ClusterContext:         getString(f.ClusterContext),
		Namespace:              getString(f.Namespace),
		KubeConfig:             getString(f.KubeConfig),
		Components:             getStringSlice(f.Components),
		K8sVersion:             getString(f.K8sVersion),
		Parallel:               parallel,
		Tolerations:            tolerations,
		AllNamespaces:          getBool(f.AllNamespaces),
		NodeCollectorNamespace: getString(f.NodeCollectorNamespace),
		ExcludeNodes:           exludeNodeLabels,
	}, nil
}

func optionToTolerations(tolerationsOptions []string) ([]corev1.Toleration, error) {
	tolerations := make([]corev1.Toleration, 0)
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
		if len(keyValue[1]) == 0 {
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
		}
		toleration.TolerationSeconds = lo.ToPtr(int64(tolerationSec))
		tolerations = append(tolerations, toleration)
	}
	return tolerations, nil
}
