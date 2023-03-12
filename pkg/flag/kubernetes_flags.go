package flag

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/samber/lo"
	corev1 "k8s.io/api/core/v1"
)

var (
	ClusterContextFlag = Flag{
		Name:       "context",
		ConfigName: "kubernetes.context",
		Value:      "",
		Usage:      "specify a context to scan",
		Aliases: []Alias{
			{Name: "ctx"},
		},
	}
	K8sNamespaceFlag = Flag{
		Name:       "namespace",
		ConfigName: "kubernetes.namespace",
		Shorthand:  "n",
		Value:      "",
		Usage:      "specify a namespace to scan",
	}
	KubeConfigFlag = Flag{
		Name:       "kubeconfig",
		ConfigName: "kubernetes.kubeconfig",
		Value:      "",
		Usage:      "specify the kubeconfig file path to use",
	}
	ComponentsFlag = Flag{
		Name:       "components",
		ConfigName: "kubernetes.components",
		Value: []string{
			"workload",
			"infra",
		},
		Usage: "specify which components to scan",
	}
	K8sVersionFlag = Flag{
		Name:       "k8s-version",
		ConfigName: "kubernetes.k8s.version",
		Value:      "",
		Usage:      "specify k8s version to validate outdated api by it (example: 1.21.0)",
	}
	TolerationsFlag = Flag{
		Name:       "tolerations",
		ConfigName: "kubernetes.tolerations",
		Value:      []string{},
		Usage:      "specify node-collector job tolerations (example: key1=value1:NoExecute,key2=value2:NoSchedule)",
	}
)

type K8sFlagGroup struct {
	ClusterContext *Flag
	Namespace      *Flag
	KubeConfig     *Flag
	Components     *Flag
	K8sVersion     *Flag
	Tolerations    *Flag
}

type K8sOptions struct {
	ClusterContext string
	Namespace      string
	KubeConfig     string
	Components     []string
	K8sVersion     string
	Tolerations    []corev1.Toleration
}

func NewK8sFlagGroup() *K8sFlagGroup {
	return &K8sFlagGroup{
		ClusterContext: &ClusterContextFlag,
		Namespace:      &K8sNamespaceFlag,
		KubeConfig:     &KubeConfigFlag,
		Components:     &ComponentsFlag,
		K8sVersion:     &K8sVersionFlag,
		Tolerations:    &TolerationsFlag,
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
		f.Tolerations,
	}
}

func (f *K8sFlagGroup) ToOptions() (K8sOptions, error) {
	tolerations, err := optionToTolerations(getStringSlice(f.Tolerations))
	if err != nil {
		return K8sOptions{}, err
	}
	return K8sOptions{
		ClusterContext: getString(f.ClusterContext),
		Namespace:      getString(f.Namespace),
		KubeConfig:     getString(f.KubeConfig),
		Components:     getStringSlice(f.Components),
		K8sVersion:     getString(f.K8sVersion),
		Tolerations:    tolerations,
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
