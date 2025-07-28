package commands

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/aquasecurity/trivy/pkg/log"
	xos "github.com/aquasecurity/trivy/pkg/x/os"
)

// NotifyContext returns a context that is canceled when SIGINT or SIGTERM is received.
// It also ensures cleanup of temporary files when the signal is received.
//
// When a signal is received, Trivy will attempt to gracefully shut down by canceling
// the context and waiting for all operations to complete. If users want to force an
// immediate exit, they can send a second SIGINT or SIGTERM signal.
func NotifyContext(parent context.Context) context.Context {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)

	// Start a goroutine to handle cleanup when context is done
	go func() {
		<-ctx.Done()

		// Log that we're shutting down gracefully
		log.Info("Received signal, attempting graceful shutdown...")
		log.Info("Press Ctrl+C again to force exit")

		// Perform cleanup
		if err := Cleanup(); err != nil {
			log.Debug("Failed to clean up temporary files", log.Err(err))
		}

		// Clean up signal handling
		// After calling stop(), a second signal will cause immediate termination
		stop()
	}()

	return ctx
}

// Cleanup performs cleanup tasks before Trivy exits
func Cleanup() error {
	return xos.Cleanup()
}
