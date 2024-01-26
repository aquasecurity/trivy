package cloudtrail

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt adapts a CloudTrail instance
func Adapt(cfFile parser.FileContext) cloudtrail.CloudTrail {
	return cloudtrail.CloudTrail{
		Trails: getCloudTrails(cfFile),
	}
}
