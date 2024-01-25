package cloudfront

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Cloudfront struct {
	Distributions []Distribution
}

type Distribution struct {
	Metadata               defsecTypes.MisconfigMetadata
	WAFID                  defsecTypes.StringValue
	Logging                Logging
	DefaultCacheBehaviour  CacheBehaviour
	OrdererCacheBehaviours []CacheBehaviour
	ViewerCertificate      ViewerCertificate
}

type Logging struct {
	Metadata defsecTypes.MisconfigMetadata
	Bucket   defsecTypes.StringValue
}

type CacheBehaviour struct {
	Metadata             defsecTypes.MisconfigMetadata
	ViewerProtocolPolicy defsecTypes.StringValue
}

const (
	ViewerPolicyProtocolAllowAll        = "allow-all"
	ViewerPolicyProtocolHTTPSOnly       = "https-only"
	ViewerPolicyProtocolRedirectToHTTPS = "redirect-to-https"
)

const (
	ProtocolVersionTLS1_2 = "TLSv1.2_2021"
)

type ViewerCertificate struct {
	Metadata                     defsecTypes.MisconfigMetadata
	CloudfrontDefaultCertificate defsecTypes.BoolValue
	SSLSupportMethod             defsecTypes.StringValue
	MinimumProtocolVersion       defsecTypes.StringValue
}
