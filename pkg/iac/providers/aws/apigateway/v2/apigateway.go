package v2

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type APIGateway struct {
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
	Metadata     defsecTypes.Metadata
	Name         defsecTypes.StringValue
	ProtocolType defsecTypes.StringValue
	Stages       []Stage
}

type Stage struct {
	Metadata      defsecTypes.Metadata
	Name          defsecTypes.StringValue
	AccessLogging AccessLogging
}

type AccessLogging struct {
	Metadata              defsecTypes.Metadata
	CloudwatchLogGroupARN defsecTypes.StringValue
}

type DomainName struct {
	Metadata       defsecTypes.Metadata
	Name           defsecTypes.StringValue
	SecurityPolicy defsecTypes.StringValue
}
