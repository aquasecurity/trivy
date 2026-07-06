package cloudfront

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Cloudfront struct {
	Distributions []Distribution
}

type Distribution struct {
	Metadata               iacTypes.Metadata
	WAFID                  iacTypes.StringValue
	Logging                Logging
	DefaultCacheBehaviour  CacheBehaviour
	OrdererCacheBehaviours []CacheBehaviour
	ViewerCertificate      ViewerCertificate
}

type LoggingV2 struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type Logging struct {
	Metadata iacTypes.Metadata
	Bucket   iacTypes.StringValue
	V2       LoggingV2
}

type CacheBehaviour struct {
	Metadata             iacTypes.Metadata
	ViewerProtocolPolicy iacTypes.StringValue
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
	Metadata                     iacTypes.Metadata
	CloudfrontDefaultCertificate iacTypes.BoolValue
	SSLSupportMethod             iacTypes.StringValue
	MinimumProtocolVersion       iacTypes.StringValue
}
