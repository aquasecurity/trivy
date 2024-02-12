package v1

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type APIGateway struct {
	APIs        []API
	DomainNames []DomainName
}

type API struct {
	Metadata  defsecTypes.Metadata
	Name      defsecTypes.StringValue
	Stages    []Stage
	Resources []Resource
}

type Stage struct {
	Metadata           defsecTypes.Metadata
	Name               defsecTypes.StringValue
	AccessLogging      AccessLogging
	XRayTracingEnabled defsecTypes.BoolValue
	RESTMethodSettings []RESTMethodSettings
}

type Resource struct {
	Metadata defsecTypes.Metadata
	Methods  []Method
}

type AccessLogging struct {
	Metadata              defsecTypes.Metadata
	CloudwatchLogGroupARN defsecTypes.StringValue
}

type RESTMethodSettings struct {
	Metadata           defsecTypes.Metadata
	Method             defsecTypes.StringValue
	CacheDataEncrypted defsecTypes.BoolValue
	CacheEnabled       defsecTypes.BoolValue
}

const (
	AuthorizationNone             = "NONE"
	AuthorizationCustom           = "CUSTOM"
	AuthorizationIAM              = "AWS_IAM"
	AuthorizationCognitoUserPools = "COGNITO_USER_POOLS"
)

type Method struct {
	Metadata          defsecTypes.Metadata
	HTTPMethod        defsecTypes.StringValue
	AuthorizationType defsecTypes.StringValue
	APIKeyRequired    defsecTypes.BoolValue
}

type DomainName struct {
	Metadata       defsecTypes.Metadata
	Name           defsecTypes.StringValue
	SecurityPolicy defsecTypes.StringValue
}
