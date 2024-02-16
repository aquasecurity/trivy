package rds

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	parser2 "github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getParameterGroups(ctx parser2.FileContext) (parametergroups []rds.ParameterGroups) {

	for _, r := range ctx.GetResourcesByType("AWS::RDS::DBParameterGroup") {

		paramgroup := rds.ParameterGroups{
			Metadata:               r.Metadata(),
			DBParameterGroupName:   r.GetStringProperty("DBParameterGroupName"),
			DBParameterGroupFamily: r.GetStringProperty("DBParameterGroupFamily"),
			Parameters:             getParameters(r),
		}

		parametergroups = append(parametergroups, paramgroup)
	}

	return parametergroups
}

func getParameters(r *parser2.Resource) (parameters []rds.Parameters) {

	dBParam := r.GetProperty("Parameters")

	if dBParam.IsNil() || dBParam.IsNotList() {
		return parameters
	}

	for _, dbp := range dBParam.AsList() {
		parameters = append(parameters, rds.Parameters{
			Metadata:       dbp.Metadata(),
			ParameterName:  types.StringDefault("", dbp.Metadata()),
			ParameterValue: types.StringDefault("", dbp.Metadata()),
		})
	}
	return parameters
}
