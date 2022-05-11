package eks

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckEnableControlPlaneLogging = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0038",
		Provider:    providers.AWSProvider,
		Service:     "eks",
		ShortCode:   "enable-control-plane-logging",
		Summary:     "EKS Clusters should have cluster control plane logging turned on",
		Impact:      "Logging provides valuable information about access and usage",
		Resolution:  "Enable logging for the EKS control plane",
		Explanation: `By default cluster control plane logging is not turned on. Logging is available for audit, api, authenticator, controllerManager and scheduler. All logging should be turned on for cluster control plane.`,
		Links: []string{
			"https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableControlPlaneLoggingGoodExamples,
			BadExamples:         terraformEnableControlPlaneLoggingBadExamples,
			Links:               terraformEnableControlPlaneLoggingLinks,
			RemediationMarkdown: terraformEnableControlPlaneLoggingRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.EKS.Clusters {
			if cluster.Logging.API.IsFalse() {
				results.Add(
					"Control plane API logging is not enabled.",
					cluster.Logging.API,
				)
			} else {
				results.AddPassed(&cluster, "Cluster plane API logging enabled")
			}

			if cluster.Logging.Audit.IsFalse() {
				results.Add(
					"Control plane audit logging is not enabled.",
					cluster.Logging.Audit,
				)
			} else {
				results.AddPassed(&cluster, "Cluster plane audit logging enabled")
			}

			if cluster.Logging.Authenticator.IsFalse() {
				results.Add(
					"Control plane authenticator logging is not enabled.",
					cluster.Logging.Authenticator,
				)
			} else {
				results.AddPassed(&cluster, "Cluster plane authenticator logging enabled")
			}

			if cluster.Logging.ControllerManager.IsFalse() {
				results.Add(
					"Control plane controller manager logging is not enabled.",
					cluster.Logging.ControllerManager,
				)
			} else {
				results.AddPassed(&cluster, "Cluster plane manager logging enabled")
			}

			if cluster.Logging.Scheduler.IsFalse() {
				results.Add(
					"Control plane scheduler logging is not enabled.",
					cluster.Logging.Scheduler,
				)
			} else {
				results.AddPassed(&cluster, "Cluster plane scheduler logging enabled")
			}

		}
		return
	},
)
