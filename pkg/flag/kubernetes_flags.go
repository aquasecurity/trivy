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

type K8sFlagGroup struct {
	ClusterContext *Flag
	Namespace      *Flag
}

type K8sOptions struct {
	ClusterContext string
	Namespace      string
}

func NewK8sFlagGroup() *K8sFlagGroup {
	return &K8sFlagGroup{
		ClusterContext: lo.ToPtr(ClusterContextFlag),
		Namespace:      lo.ToPtr(K8sNamespaceFlag),
	}
}

func (f *K8sFlagGroup) flags() []*Flag {
	return []*Flag{f.ClusterContext, f.Namespace}
}

func (f *K8sFlagGroup) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.flags() {
		addFlag(cmd, flag)
	}
}

func (f *K8sFlagGroup) Bind(cmd *cobra.Command) error {
	for _, flag := range f.flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *K8sFlagGroup) ToOptions() K8sOptions {
	return K8sOptions{
		ClusterContext: getString(f.ClusterContext),
		Namespace:      getString(f.Namespace),
	}
}
