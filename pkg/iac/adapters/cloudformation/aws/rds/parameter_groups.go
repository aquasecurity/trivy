package rds

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func getParameterGroups(ctx parser.FileContext) (parametergroups []rds.ParameterGroups) {

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

func getParameters(r *parser.Resource) (parameters []rds.Parameters) {

	dBParam := r.GetProperty("Parameters")

	// TODO: parameters is JSON
	// https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-rds-dbparametergroup.html#cfn-rds-dbparametergroup-parameters
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
