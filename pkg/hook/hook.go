package hook

import (
	"context"
	"sort"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

var hooks = make(map[string]Hook)

type Hook interface {
	// Name returns the name of the hook.
	Name() string
}

// RunHook is a hook that is called before and after all the processes.
type RunHook interface {
	Hook

	// PreRun is called before all the processes.
	PreRun(ctx context.Context, opts flag.Options) error

	// PostRun is called after all the processes.
	PostRun(ctx context.Context, opts flag.Options) error
}

// ScanHook is a hook that is called before and after the scan.
type ScanHook interface {
	Hook

	// PreScan is called before the scan. It can modify the scan target.
	// It may be called on the server side in client/server mode.
	PreScan(ctx context.Context, target *types.ScanTarget, opts types.ScanOptions) error

	// PostScan is called after the scan. It can modify the results.
	// It may be called on the server side in client/server mode.
	// NOTE: Wasm modules cannot directly modify the passed results,
	//       so it returns a copy of the results.
	PostScan(ctx context.Context, results types.Results) (types.Results, error)
}

// ReportHook is a hook that is called before and after the report is written.
type ReportHook interface {
	Hook

	// PreReport is called before the report is written.
	// It can modify the report. It is called on the client side.
	PreReport(ctx context.Context, report *types.Report, opts flag.Options) error

	// PostReport is called after the report is written.
	// It can modify the report. It is called on the client side.
	PostReport(ctx context.Context, report *types.Report, opts flag.Options) error
}

func Register(s Hook) {
	// Avoid duplication
	hooks[s.Name()] = s
}

func Deregister(name string) {
	delete(hooks, name)
}

func Hooks() []string {
	names := lo.Keys(hooks)
	sort.Strings(names)
	return names
}

func PreRun(ctx context.Context, opts flag.Options) error {
	for _, s := range hooks {
		h, ok := s.(RunHook)
		if !ok {
			continue
		}
		if err := h.PreRun(ctx, opts); err != nil {
			return xerrors.Errorf("%s pre run error: %w", s.Name(), err)
		}
	}
	return nil
}

func PostRun(ctx context.Context, opts flag.Options) error {
	for _, s := range hooks {
		h, ok := s.(RunHook)
		if !ok {
			continue
		}
		if err := h.PostRun(ctx, opts); err != nil {
			return xerrors.Errorf("%s post run error: %w", s.Name(), err)
		}
	}
	return nil
}

func PreScan(ctx context.Context, target *types.ScanTarget, options types.ScanOptions) error {
	for _, s := range hooks {
		h, ok := s.(ScanHook)
		if !ok {
			continue
		}
		if err := h.PreScan(ctx, target, options); err != nil {
			return xerrors.Errorf("%s pre scan error: %w", s.Name(), err)
		}
	}
	return nil
}

func PostScan(ctx context.Context, results types.Results) (types.Results, error) {
	var err error
	for _, s := range hooks {
		h, ok := s.(ScanHook)
		if !ok {
			continue
		}
		results, err = h.PostScan(ctx, results)
		if err != nil {
			return nil, xerrors.Errorf("%s post scan error: %w", s.Name(), err)
		}
	}
	return results, nil
}

func PreReport(ctx context.Context, report *types.Report, opts flag.Options) error {
	for _, s := range hooks {
		h, ok := s.(ReportHook)
		if !ok {
			continue
		}
		if err := h.PreReport(ctx, report, opts); err != nil {
			return xerrors.Errorf("%s pre report error: %w", s.Name(), err)
		}
	}
	return nil
}

func PostReport(ctx context.Context, report *types.Report, opts flag.Options) error {
	for _, s := range hooks {
		h, ok := s.(ReportHook)
		if !ok {
			continue
		}
		if err := h.PostReport(ctx, report, opts); err != nil {
			return xerrors.Errorf("%s post report error: %w", s.Name(), err)
		}
	}
	return nil
}
