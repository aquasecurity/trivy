package functions

type DeploymentData interface {
	GetParameter(name string) interface{}
	GetVariable(variableName string) interface{}
	GetEnvVariable(envVariableName string) interface{}
}

func Deployment(deploymentProvider DeploymentData, args ...interface{}) interface{} {

	/*

		{
		  "name": "",
		  "properties": {
		    "templateLink": {
		      "uri": ""
		    },
		    "template": {
		      "$schema": "",
		      "contentVersion": "",
		      "parameters": {},
		      "variables": {},
		      "resources": [],
		      "outputs": {}
		    },
		    "templateHash": "",
		    "parameters": {},
		    "mode": "",
		    "provisioningState": ""
		  }
		}

	*/

	return nil
}

func Environment(envProvider DeploymentData, args ...interface{}) interface{} {
	if len(args) == 0 {
		return nil
	}

	envVarName, ok := args[0].(string)
	if !ok {
		return nil
	}
	return envProvider.GetEnvVariable(envVarName)
}

func Variables(varProvider DeploymentData, args ...interface{}) interface{} {
	if len(args) == 0 {
		return nil
	}

	varName, ok := args[0].(string)
	if !ok {
		return nil
	}
	return varProvider.GetVariable(varName)
}

func Parameters(paramProvider DeploymentData, args ...interface{}) interface{} {
	if len(args) == 0 {
		return nil
	}

	paramName, ok := args[0].(string)
	if !ok {
		return nil
	}

	return paramProvider.GetParameter(paramName)

}
