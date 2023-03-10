package weakpass

import (
	"context"
	"strings"
	"testing"

	"github.com/chaitin/veinmind-common-go/service/report/event"

	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-weakpass/model"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/stretchr/testify/assert"
)

func TestWeakPassAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name       string
		input      analyzer.AnalysisInput
		wantResult *analyzer.AnalysisResult
		wantError  string
	}{
		{
			name: "happy path",
			input: analyzer.AnalysisInput{
				FilePath: "/etc/shadow",
				Content:  strings.NewReader("root:*:18981:0:99999:7:::\ndaemon:*:18981:0:99999:7:::\nbin:*:18981:0:99999:7:::\nsys:*:18981:0:99999:7:::\nsync:*:18981:0:99999:7:::\ngames:*:18981:0:99999:7:::\nman:*:18981:0:99999:7:::\nlp:*:18981:0:99999:7:::\nmail:*:18981:0:99999:7:::\nnews:*:18981:0:99999:7:::\nuucp:*:18981:0:99999:7:::\nproxy:*:18981:0:99999:7:::\nwww-data:*:18981:0:99999:7:::\nbackup:*:18981:0:99999:7:::\nlist:*:18981:0:99999:7:::\nirc:*:18981:0:99999:7:::\ngnats:*:18981:0:99999:7:::\nnobody:*:18981:0:99999:7:::\n_apt:*:18981:0:99999:7:::\nmysql:!:18982::::::\ntest:$6$eCDNQkBdZonAPKY/$OTmiNknRSubK6KmhIysAfjeQysoz37DklWpHhnzwYQ2PFHHDIuP2PEMRP13K7oGIwcZ/lNKl36NctRlQYsOla/:19227:0:99999:7:::"),
			},
			wantResult: &analyzer.AnalysisResult{
				WeakPass: []model.WeakpassResult{model.WeakpassResult{
					Username:    "test",
					Password:    "surfing",
					Filepath:    "/etc/shadow",
					ServiceType: event.SSH,
				}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := weakPassAnalyzer{}
			res, err := a.Analyze(context.Background(), test.input)

			if test.wantError != "" {
				assert.NotNil(t, err)
				assert.Equal(t, test.wantError, err.Error())
			} else {
				assert.Nil(t, err)
				assert.Equal(t, test.wantResult, res)
			}
		})
	}
}
