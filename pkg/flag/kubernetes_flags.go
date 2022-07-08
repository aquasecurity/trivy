package flag

import (
	"github.com/samber/lo"
	"github.com/spf13/cobra"
)

var (
	ClusterContextFlag = Flag{
		Name:       "context",
		ConfigName: "kubernetes.context",
		Value:      "",
		Usage:      "specify a context to scan",
	}
	K8sNamespaceFlag = Flag{
		Name:       "namespace",
		ConfigName: "kubernetes.namespace",
		Value:      "",
		Usage:      "specify a namespace to sca",
	}
)

type KubernetesFlags struct {
	ClusterContext *Flag
	Namespace      *Flag
}

type KubernetesOptions struct {
	ClusterContext string
	Namespace      string
}

func NewKubernetesDefaultFlags() *KubernetesFlags {
	return &KubernetesFlags{
		ClusterContext: lo.ToPtr(ClusterContextFlag),
		Namespace:      lo.ToPtr(K8sNamespaceFlag),
	}
}

func (f *KubernetesFlags) flags() []*Flag {
	return []*Flag{f.ClusterContext, f.Namespace}
}

func (f *KubernetesFlags) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.flags() {
		addFlag(cmd, flag)
	}
}

func (f *KubernetesFlags) Bind(cmd *cobra.Command) error {
	for _, flag := range f.flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *KubernetesFlags) ToOptions() KubernetesOptions {
	return KubernetesOptions{
		ClusterContext: getString(f.ClusterContext),
		Namespace:      getString(f.Namespace),
	}
}
