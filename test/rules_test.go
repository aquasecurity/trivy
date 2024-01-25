package test

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/rules"
)

func TestAVDIDs(t *testing.T) {
	existing := make(map[string]struct{})
	for _, rule := range rules.GetRegistered(framework.ALL) {
		t.Run(rule.LongID(), func(t *testing.T) {
			if rule.GetRule().AVDID == "" {
				t.Errorf("Rule has no AVD ID: %#v", rule)
				return
			}
			if _, ok := existing[rule.GetRule().AVDID]; ok {
				t.Errorf("Rule detected with duplicate AVD ID: %s", rule.GetRule().AVDID)
			}
		})
		existing[rule.GetRule().AVDID] = struct{}{}
	}
}

//func TestRulesAgainstExampleCode(t *testing.T) {
//	for _, rule := range rules.GetRegistered(framework.ALL) {
//		testName := fmt.Sprintf("%s/%s", rule.GetRule().AVDID, rule.LongID())
//		t.Run(testName, func(t *testing.T) {
//			rule := rule
//			t.Parallel()
//
//			t.Run("avd docs", func(t *testing.T) {
//				provider := strings.ToLower(rule.GetRule().Provider.ConstName())
//				service := strings.ToLower(strings.ReplaceAll(rule.GetRule().Service, "-", ""))
//				_, err := os.Stat(filepath.Join("..", "avd_docs", provider, service, rule.GetRule().AVDID, "docs.md"))
//				require.NoError(t, err)
//			})
//		})
//	}
//}
