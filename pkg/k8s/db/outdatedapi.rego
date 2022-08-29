package  builtin.kubernetes.KDV001

import data.lib.kubernetes
import data.lib.result
import data.lib.utils

__rego_metadata__ := {
  "id": "KDV001",
  "avd_id": "KDV01-KDV-0001",
  "title": "Evaluate k8s deprecated and removed APIs",
  "short_code": "evaluate-k8s-deprecated-removed-apis",
  "severity": "HIGH",
  "description": sprintf("apiVersion '%s' and kind '%s' has been deprecated on: '%s' and planned for removal on:'%s'",[input.apiVersion,input.kind,recommendedVersions[input.apiVersion][input.kind].deprecated_version,recommendedVersions[input.apiVersion][input.kind].removed_version]),
  "recommended_actions": sprintf("It recommended to move to the new replacement API:'%s'",[recommendedVersions[input.apiVersion][input.kind].replacement_version]),
  "url": sprintf("%s",[recommendedVersions[input.apiVersion][input.kind].ref]),
}

__rego_input__ := {
  "combine": false,
  "selector": [{"type": "kubernetes"}],
}


recommendedVersions := $1
deny[res] {
 _ = recommendedVersions[input.apiVersion][input.kind]
  msg := sprintf("apiVersion '%s' and kind ‘%s' has been deprecated on: '%s' and planned for removal on:'%s'",[input.apiVersion,input.kind,recommendedVersions[input.apiVersion][input.kind].deprecated_version,recommendedVersions[input.apiVersion][input.kind].removed_version])
  res := result.new(msg, input)
}