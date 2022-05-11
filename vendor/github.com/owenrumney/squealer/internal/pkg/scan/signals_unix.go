//go:build linux || bsd || darwin || freebsd
// +build linux bsd darwin freebsd

package scan

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func (s *gitScanner) monitorSignals(processes int, wg *sync.WaitGroup) {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGTSTP)
	go func() {
		for range c {
			log.Info("Shutting down workers and exiting...")
			for i := 0; i < processes; i++ {
				wg.Done()
			}
			os.Exit(0)
		}
	}()
}
