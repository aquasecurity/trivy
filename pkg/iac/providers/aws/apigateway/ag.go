package apigateway

import (
	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"
	v2 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v2"
)

// DefaultSecurityPolicy is assigned by API Gateway to a custom domain name
// that has no explicit security policy:
// https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html#apigateway-security-policies-default
const DefaultSecurityPolicy = "TLS_1_2"

type APIGateway struct {
	V1 v1.APIGateway
	V2 v2.APIGateway
}
