package apigateway

import "github.com/aquasecurity/defsec/parsers/types"

type APIGateway struct {
	types.Metadata
	APIs        []API
	DomainNames []DomainName
}

const (
	ProtocolTypeUnknown   string = ""
	ProtocolTypeREST      string = "REST"
	ProtocolTypeHTTP      string = "HTTP"
	ProtocolTypeWebsocket string = "WEBSOCKET"
)

type API struct {
	types.Metadata
	Name         types.StringValue
	Version      types.IntValue
	ProtocolType types.StringValue
	Stages       []Stage
	RESTMethods  []RESTMethod
}

type Stage struct {
	types.Metadata
	Name               types.StringValue
	Version            types.IntValue
	AccessLogging      AccessLogging
	RESTMethodSettings RESTMethodSettings
	XRayTracingEnabled types.BoolValue
}

type AccessLogging struct {
	types.Metadata
	CloudwatchLogGroupARN types.StringValue
}

type RESTMethodSettings struct {
	types.Metadata
	CacheDataEncrypted types.BoolValue
}

const (
	AuthorizationNone             = "NONE"
	AuthorizationCustom           = "CUSTOM"
	AuthorizationIAM              = "AWS_IAM"
	AuthorizationCognitoUserPools = "COGNITO_USER_POOLS"
)

type RESTMethod struct {
	types.Metadata
	HTTPMethod        types.StringValue
	AuthorizationType types.StringValue
	APIKeyRequired    types.BoolValue
}

type DomainName struct {
	types.Metadata
	Name           types.StringValue
	Version        types.IntValue
	SecurityPolicy types.StringValue
}
