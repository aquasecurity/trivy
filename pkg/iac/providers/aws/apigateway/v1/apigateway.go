package v1

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type APIGateway struct {
	APIs        []API
	DomainNames []DomainName
}

type API struct {
	Metadata  iacTypes.Metadata
	Name      iacTypes.StringValue
	Stages    []Stage
	Resources []Resource
}

type Stage struct {
	Metadata           iacTypes.Metadata
	Name               iacTypes.StringValue
	AccessLogging      AccessLogging
	XRayTracingEnabled iacTypes.BoolValue
	RESTMethodSettings []RESTMethodSettings
}

type Resource struct {
	Metadata iacTypes.Metadata
	Methods  []Method
}

type AccessLogging struct {
	Metadata              iacTypes.Metadata
	CloudwatchLogGroupARN iacTypes.StringValue
}

type RESTMethodSettings struct {
	Metadata           iacTypes.Metadata
	Method             iacTypes.StringValue
	CacheDataEncrypted iacTypes.BoolValue
	CacheEnabled       iacTypes.BoolValue
}

const (
	AuthorizationNone             = "NONE"
	AuthorizationCustom           = "CUSTOM"
	AuthorizationIAM              = "AWS_IAM"
	AuthorizationCognitoUserPools = "COGNITO_USER_POOLS"
)

type Method struct {
	Metadata          iacTypes.Metadata
	HTTPMethod        iacTypes.StringValue
	AuthorizationType iacTypes.StringValue
	APIKeyRequired    iacTypes.BoolValue
}

type DomainName struct {
	Metadata       iacTypes.Metadata
	Name           iacTypes.StringValue
	SecurityPolicy iacTypes.StringValue
}
