package ecs

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getClusters(ctx parser.FileContext) (clusters []ecs.Cluster) {

	clusterResources := ctx.GetResourcesByType("AWS::ECS::Cluster")

	for _, r := range clusterResources {

		cluster := ecs.Cluster{
			Metadata: r.Metadata(),
			Settings: getClusterSettings(r),
		}

		clusters = append(clusters, cluster)

	}

	return clusters
}

func getClusterSettings(r *parser.Resource) ecs.ClusterSettings {

	clusterSettings := ecs.ClusterSettings{
		Metadata:                 r.Metadata(),
		ContainerInsightsEnabled: types.BoolDefault(false, r.Metadata()),
	}

	clusterSettingMap := r.GetProperty("ClusterSettings")
	if clusterSettingMap.IsNil() || clusterSettingMap.IsNotList() {
		return clusterSettings
	}

	clusterSettings.Metadata = clusterSettingMap.Metadata()

	for _, setting := range clusterSettingMap.AsList() {
		checkProperty(setting, &clusterSettings)
	}

	return clusterSettings
}

func checkProperty(setting *parser.Property, clusterSettings *ecs.ClusterSettings) {
	settingMap := setting.AsMap()
	name := settingMap["Name"]
	if name.IsNotNil() && name.EqualTo("containerInsights") {
		value := settingMap["Value"]
		if value.IsNotNil() && value.EqualTo("enabled") {
			clusterSettings.ContainerInsightsEnabled = types.Bool(true, value.Metadata())
		}
	}
}
