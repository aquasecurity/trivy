package db

import _ "embed"

var (
	//go:embed outdatedapi.rego
	outdatedAPIPolicy string
)

var outdatedAPIData = `{
  "batch/v1": {
    "Job": {
      "deprecated_version": "v1.21",
      "replacement_version": "batch.v1.CronJobList",
      "removed_version": "v1.25",
      "ref": "https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/api/batch/v1beta1/zz_generated.prerelease-lifecycle.go"
    }
  },
  "flowcontrol/v1beta1": {
    "PriorityLevelConfiguration": {
      "deprecated_version": "v1.23",
      "replacement_version": "flowcontrol.apiserver.k8s.io.v1beta2.PriorityLevelConfiguration",
      "removed_version": "v1.26",
      "ref": "https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/api/flowcontrol/v1beta1/zz_generated.prerelease-lifecycle.go"
    }
  }
}
`

//FetchOutdatedApiData @todo replace this with gettting outdated api from trivy-db
func FetchOutdatedApiData() string {
	return outdatedAPIData
}

//GetOutDatedAPIPolicy @todo replace this with gettting outdated api from trivy-db
func GetOutDatedAPIPolicy() string {
	return outdatedAPIPolicy
}
