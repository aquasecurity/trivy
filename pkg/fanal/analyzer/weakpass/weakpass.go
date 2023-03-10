package weakpass

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Jeffail/tunny"
	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-weakpass/model"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	_ "github.com/chaitin/veinmind-tools/plugins/go/veinmind-weakpass/dict"
	_ "github.com/chaitin/veinmind-tools/plugins/go/veinmind-weakpass/hash"
	"github.com/chaitin/veinmind-tools/plugins/go/veinmind-weakpass/service"
	"golang.org/x/xerrors"
	"k8s.io/utils/strings/slices"
)

func init() {
	requiredFiles = getRequiredFile()
	analyzer.RegisterAnalyzer(&weakPassAnalyzer{})
}

func getRequiredFile() (pathList []string) {
	svcMap := service.GetAllModules()

	for _, mod := range svcMap {

		var tmp []string
		for _, v := range mod.FilePath() {
			path := strings.TrimPrefix(v, "/")
			tmp = append(tmp, path)
			serviceMap[path] = mod
		}
		pathList = append(pathList, tmp...)
	}

	return
}

const version = 1

var requiredFiles []string
var serviceMap = make(map[string]service.IService)

type weakPassAnalyzer struct{}

func (a weakPassAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var weakPassResults []model.WeakpassResult
	mod := serviceMap[input.FilePath]

	hash, err := service.GetHash(mod.Name())
	if err != nil {
		log.Logger.Error(err)
		return &analyzer.AnalysisResult{}, nil
	}
	dict := service.GetDict(mod.Name())

	var weakPassResultsLock sync.Mutex
	pool := tunny.NewFunc(2, func(opt interface{}) interface{} {
		bruteOpt, ok := opt.(model.BruteOption)
		if !ok {

			return xerrors.Errorf("please use BruteOption")
		}
		match, err := hash.Match(bruteOpt.Records.Password, bruteOpt.Guess)
		if err != nil {
			return err
		}
		if match {
			w := model.WeakpassResult{
				Username:    bruteOpt.Records.Username,
				Password:    bruteOpt.Guess,
				Filepath:    input.FilePath,
				ServiceType: service.GetType(mod),
			}
			weakPassResultsLock.Lock()
			weakPassResults = append(weakPassResults, w)
			weakPassResultsLock.Unlock()
			return true
		}
		return false
	})
	defer pool.Close()

	records, err := mod.GetRecords(input.Content)
	if err != nil {
		log.Logger.Error(err)
		return &analyzer.AnalysisResult{}, nil
	}

	for _, item := range records {
		for _, guess := range dict {
			match, err := pool.ProcessTimed(model.BruteOption{
				Records: item,
				Guess:   guess,
			}, 5*time.Second)

			if err != nil {
				log.Logger.Error(err)
				continue
			}
			if v, ok := match.(bool); ok {
				if v {
					break
				}
			}
		}
	}
	// Report
	if len(weakPassResults) > 0 {
		log.Logger.Debug("weak pass :", weakPassResults)
	}
	return &analyzer.AnalysisResult{WeakPass: weakPassResults}, nil
}

func (a weakPassAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a weakPassAnalyzer) Type() analyzer.Type {
	return analyzer.TypeWeakPassWord
}

func (a weakPassAnalyzer) Version() int {
	return version
}
