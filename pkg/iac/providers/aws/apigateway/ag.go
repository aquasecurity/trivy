package apigateway

import (
	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"
	v2 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v2"
)

type APIGateway struct {
	V1 v1.APIGateway
	V2 v2.APIGateway
}
