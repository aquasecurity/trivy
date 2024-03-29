package v2

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
	Metadata     iacTypes.Metadata
	Name         iacTypes.StringValue
	ProtocolType iacTypes.StringValue
	Stages       []Stage
}

type Stage struct {
	Metadata      iacTypes.Metadata
	Name          iacTypes.StringValue
	AccessLogging AccessLogging
}

type AccessLogging struct {
	Metadata              iacTypes.Metadata
	CloudwatchLogGroupARN iacTypes.StringValue
}

type DomainName struct {
	Metadata       iacTypes.Metadata
	Name           iacTypes.StringValue
	SecurityPolicy iacTypes.StringValue
}
