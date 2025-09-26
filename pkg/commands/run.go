package commands

import (
	"context"
	"errors"
	"fmt"

	bberrors "go.etcd.io/bbolt/errors"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/version/doc"
)

const (
	troubleshootingDocPath = "/docs/references/troubleshooting/"
	lockDocFragment        = "database-and-cache-lock-errors"
	timeoutDocFragment     = "timeout"
)

// Run builds the CLI application and executes it with centralized error handling.
func Run(ctx context.Context) error {
	app := NewApp()
	if err := app.ExecuteContext(ctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.WarnContext(ctx, fmt.Sprintf("Provide a higher timeout value, see %s", doc.URL(troubleshootingDocPath, timeoutDocFragment)))
		}
		if errors.Is(err, bberrors.ErrTimeout) {
			log.ErrorContext(ctx, fmt.Sprintf("Failed to acquire cache or database lock, see %s for troubleshooting", doc.URL(troubleshootingDocPath, lockDocFragment)))
		}
		return err
	}
	return nil
}
