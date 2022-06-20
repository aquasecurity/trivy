package handler

import (
	"context"
	"sort"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	postHandlerInits = map[types.HandlerType]postHandlerInit{}
)

type postHandlerInit func(artifact.Option) (PostHandler, error)

type PostHandler interface {
	Type() types.HandlerType
	Version() int
	Handle(context.Context, *analyzer.AnalysisResult, *types.BlobInfo) error
	Priority() int
}

// RegisterPostHandlerInit adds a constructor of post handler
func RegisterPostHandlerInit(t types.HandlerType, init postHandlerInit) {
	postHandlerInits[t] = init
}

func DeregisterPostHandler(t types.HandlerType) {
	delete(postHandlerInits, t)
}

type Manager struct {
	postHandlers []PostHandler
}

func NewManager(artifactOpt artifact.Option) (Manager, error) {
	var m Manager
	for t, handlerInit := range postHandlerInits {
		// Skip the handler if it is disabled
		if slices.Contains(artifactOpt.DisabledHandlers, t) {
			continue
		}
		handler, err := handlerInit(artifactOpt)
		if err != nil {
			return Manager{}, xerrors.Errorf("post handler %s initialize error: %w", t, err)
		}

		m.postHandlers = append(m.postHandlers, handler)
	}

	// Sort post handlers by priority
	sort.Slice(m.postHandlers, func(i, j int) bool {
		return m.postHandlers[i].Priority() > m.postHandlers[j].Priority()
	})

	return m, nil
}

func (m Manager) Versions() map[string]int {
	versions := map[string]int{}
	for _, h := range m.postHandlers {
		versions[string(h.Type())] = h.Version()
	}
	return versions
}

func (m Manager) PostHandle(ctx context.Context, result *analyzer.AnalysisResult, blob *types.BlobInfo) error {
	for _, h := range m.postHandlers {
		if err := h.Handle(ctx, result, blob); err != nil {
			return xerrors.Errorf("post handler error: %w", err)
		}
	}
	return nil
}
